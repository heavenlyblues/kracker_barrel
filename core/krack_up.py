import atexit
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
import logging
from multiprocessing import Manager, shared_memory, Lock, Queue
import numpy as np
import os, time
from pathlib import Path
from tqdm import tqdm
from core.hash_handler import HashHandler
from core.brut_gen import generate_brute_candidates, yield_brute_batches, get_brute_count
from core.mask_gen import generate_mask_candidates, yield_maskbased_batches, get_mask_count
from utils.file_io import get_number_of_passwords, yield_dictionary_batches, load_target_hash
from utils.reporter import display_summary, PURPLE, GREEN, LIGHT_YELLOW, DIM, RESET


class Kracker:
    def __init__(self, args):
        self.config = ConfigParser(args)
        self.result_handler = ResultHandler(self.config)
        self.worker_manager = WorkerManager(self.config)

    def run(self):
        try:
            print(self.config)  # Display configuration
            self.worker_manager.start_workers()
            self.result_handler.finalize_summary()
        finally:
            self.worker_manager.cleanup_shared_memory()


class ConfigParser:
    def __init__(self, args):
        self.operation = args.operation  # "dict", "brut", "mask", etc.
        self.target_file = Path ("data") / args.target_file
        self.hash_digest_with_metadata = load_target_hash(self.target_file) # List of hashes to crack
        self.hash_type = self.detect_hash_type() # argon, bcrypt, pbkfd2, scrypt, ntlm, md5, sha256, sha512
        self.path_to_passwords = Path("refs") / args.password_list if args.password_list else None
        self.batch_size = 2000 # or args.batch_size
        self.workers = os.cpu_count() # or args.workers
        self.mask_pattern = args.pattern # Mask-based attack
        self.custom_strings = args.custom if args.custom else None # Mask-based custom string to append
        self.brute_settings = dict(charset=args.charset, min=args.min, max=args.max)
        self.found_flag = Manager().dict(found=0, goal=len(self.hash_digest_with_metadata))
        self.start_time = time.time()

    def detect_hash_type(self):
        type_check = self.hash_digest_with_metadata[0].split("$", 2)[1]
        
        # Use a dictionary to map type_check to hash types
        hash_map = {
            "argon2id": "argon",
            "2b": "bcrypt",
            "pbkdf2": "pbkdf2",
            "scrypt": "scrypt",
            "ntlm": "ntlm",
            "md5": "md5",
            "sha256": "sha256",
            "sha512": "sha512"
        }

        # Return the mapped hash type or raise an error for unknown types
        try:
            return hash_map[type_check]
        except KeyError:
            raise ValueError(f"Unknown hash format: {type_check}")
        
    def __str__(self):
        return (
            f"\n{PURPLE}Kracker Configuration:{RESET}\n"
            f"  Operation: {self.operation}\n"
            f"  Target: {self.target_file}\n"
            f"  Hash type: {self.hash_type}\n"
            f"  Password list: {self.path_to_passwords}\n"
            f"  Batch size: {self.batch_size}\n"
            f"  Workers: {self.workers}\n"
        )


class BatchManager:
    def __init__(self, config, shared_array):
        self.config = config
        self.reporter = ResultHandler(config)
        self.shared_array = shared_array
        self.generator = None
        self.total_passwords = None
        self.total_batches = None
        self.max_password_length = None
        self.batches_loaded = 0
        self.free_slots = Queue(maxsize=config.workers * 3)  # Manage available slots
        for i in range(config.workers * 3):
            self.free_slots.put(i)  # Initialize all slots as free
        
    def initialize_generator(self):
        print(f"Initializing generator for operation: {self.config.operation}")
        if self.config.operation == "dict":
            # First pass: Calculate max password length
            with self.config.path_to_passwords.open("r", encoding="latin-1", errors="replace") as file:
                self.max_password_length = max(len(line.strip()) for line in file)
            print(f"Max password length: {self.max_password_length}")
            
            # Second pass: Initialize the generator
            self.generator = yield_dictionary_batches(self.config.path_to_passwords, self.config.batch_size)
            self.total_passwords = get_number_of_passwords(self.config.path_to_passwords)
            print(f"Generator initialized. Total passwords: {self.total_passwords}")
        elif self.config.operation == "brut":
            generator = generate_brute_candidates(self.config.brute_settings)
            self.generator = yield_brute_batches(generator, self.config.batch_size)
            self.total_passwords = get_brute_count(self.brute_settings)
        elif self.config.operation == "mask":
            generator = generate_mask_candidates(self.config.mask_pattern, self.config.custom_strings)
            self.generator = yield_maskbased_batches(generator, self.config.batch_size)
            self.total_passwords = get_mask_count(self.config.mask_pattern, self.config.custom_strings)
        elif self.config.operation == "rule":
            raise NotImplementedError("Rule-based attack is not implemented.")
        else:
            print(f"Unsupported operation: {self.config.operation}")
        self.total_batches = -(-self.total_passwords // self.config.batch_size)
        print(f"Batch generator initialized: {self.generator}")

    def load_batch_to_memory(self, slot_index):
        try:
            batch = next(self.generator)
            print(f"Batch retrieved: {batch}")
            shared_slot = self.shared_array[slot_index]
            for i, password in enumerate(batch):
                print(password)
                shared_slot[i, :len(password)] = np.frombuffer(password.encode(), dtype=np.uint8)
                shared_slot[i, len(password):] = 0  # Zero out remaining space
            for i in range(len(batch), self.config.batch_size):
                shared_slot[i, :] = 0  # Clear unused rows
            logging.info(f"Loaded batch into slot {slot_index}.")
            return True
        except StopIteration:
            logging.info("No more batches to load.")
            return False


class WorkerManager:
    def __init__(self, config):
        self.config = config
        self.worker_count = config.workers
        self.batches_in_memory = self.worker_count * 2
        self.shared_memory = shared_memory.SharedMemory(create=True, size=self.config.batch_size * 128 * config.workers * 3)
        self.shared_array = np.ndarray((config.workers * 3, self.config.batch_size, 128), dtype=np.uint8, buffer=self.shared_memory.buf)
        self.batch_manager = BatchManager(self.config, self.shared_array)

    def start_workers(self):
        self.batch_manager.initialize_generator()
        with ProcessPoolExecutor(max_workers=self.config.workers) as executor:
            futures = []

            # Preload initial batches
            for _ in range(min(self.config.workers * 3, self.batch_manager.total_batches)):
                slot_index = self.batch_manager.free_slots.get()
                if self.batch_manager.load_batch_to_memory(slot_index):
                    logging.info(f"Submitting batch {slot_index} to worker.")
                    futures.append(executor.submit(self.worker_task, slot_index))
                else:
                    logging.info(f"Batch {slot_index} could not be loaded.")
                    self.batch_manager.free_slots.put(slot_index)

            # Process batches dynamically
            with tqdm(
                desc=f"{PURPLE}Batch Processing{RESET}",
                total=self.batch_manager.total_batches,
                ncols=100,
                leave=True,
                ascii=True
            ) as progress_bar:
                while futures:
                    for future in as_completed(futures):
                        try:
                            results, chunk_count, slot_index = future.result()
                            self.batch_manager.reporter.update(results, chunk_count)
                            progress_bar.update(1)

                            # Reload next batch
                            if self.batch_manager.load_batch_to_memory(slot_index):
                                futures.append(executor.submit(self.worker_task, slot_index))
                            else:
                                self.batch_manager.free_slots.put(slot_index)
                        except Exception as e:
                            logging.error(f"Error processing future: {e}")
                        finally:
                            futures.remove(future)
                progress_bar.close()
        self.batch_manager.reporter.finalize_summary()


    # Process the resluts from completed futures
    def process_task_result(self, task_result):
        try:
            results, chunk_count, batch_index = task_result.result()
            logging.info(f"Processing results for batch {batch_index}. Matches: {len(results)}.")
            self.batch_manager.reporter.update(results, chunk_count)
        except Exception as e:
            logging.error(f"Error in process_task_result: {e}")
            traceback.print_exc()

        
    def worker_task(self, slot_index):
        """
        Worker function to process a specific batch.
        """
        logging.info(f"Worker started for batch {slot_index}.")
        shared_slot = self.shared_array[slot_index]
        passwords = [
            bytes(shared_slot[i]).decode('utf-8').rstrip('\x00')
            for i in range(self.config.batch_size)
            if shared_slot[i, 0] != 0
        ]
        logging.info(f"Batch {slot_index} loaded with {len(passwords)} passwords.")

        # Dynamically initialize the correct HashHandler subclass
        hash_handlers = {
            "argon": lambda x: HashHandler.Argon2Handler(x),
            "scrypt": lambda x: HashHandler.ScryptHandler(x),
            "pbkdf2": lambda x: HashHandler.PBKDF2Handler(x),
            "bcrypt": lambda x: HashHandler.BcryptHandler(x),
            "ntlm": lambda x: HashHandler.NTLMHandler(x),
            "md5": lambda x: HashHandler.MD5Handler(x),
            "sha256": lambda x: HashHandler.SHA256Handler(x), 
            "sha512": lambda x: HashHandler.SHA512Handler(x)
        }
        handler_class = hash_handlers.get(self.config.hash_type)
        if not handler_class:
            raise ValueError(f"No handler found for hash type: {self.config.hash_type}. "
                            f"Available types: {', '.join(hash_handlers.keys())}")

        # Initialize the hash handler and parse metadata
        hash_handler = handler_class(self.config.hash_digest_with_metadata)
        hash_handler.parse_hash_digest_with_metadata()
        logging.info(f"Hash handler initialized for type: {self.config.hash_type} with parameters: {hash_handler.parameters}")

        results = []
        chunk_count = 0

        # Process passwords
        for password in passwords:
            if self.config.found_flag["found"] >= self.config.found_flag["goal"]:
                break

            chunk_count += 1
            matched_password = hash_handler.verify(password)
            if matched_password:
                logging.info(f"Password matched: {matched_password}")
                results.append(matched_password)

        logging.info(f"Worker completed batch {slot_index}. Matches: {len(results)}.")
        return results, chunk_count, slot_index

    def cleanup_shared_memory(self):
        try:
            self.shared_memory.close()
            self.shared_memory.unlink()
        except Exception as e:
            print(f"Error during shared memory cleanup: {e}")


class ResultHandler:
    def __init__(self, config):
        self.config = config
        self.results = []
        self.total_count = 0
        self.summary_log = self.initialize_summary_log()

    def initialize_summary_log(self):
        if self.config.operation == "dict":
            number_of_passwords = get_number_of_passwords(self.config.path_to_passwords)
        elif self.config.operation == "brut":
            number_of_passwords = get_brute_count(self.config.brute_settings)
        elif self.config.operation == "mask":
            number_of_passwords = get_mask_count(self.config.mask_pattern, self.config.custom_strings)
        elif self.config.operation == "rule":
            number_of_passwords = 1
        
        total_batches = (number_of_passwords // self.config.batch_size) + 1
        
        return {
            "operation": self.config.operation,
            "input_file": self.config.target_file,
            "hash_type": self.config.hash_type,
            "hash_parameters": {},  # Filled later by hash handler
            "file_scanned": self.config.path_to_passwords,
            "workers": self.config.workers,
            "batches": total_batches,
            "batch_size": self.config.batch_size,
            "items": number_of_passwords,
            "total_count": 0,
            "pwned": [],
            "message": "",
            "elapsed_time": 0
        }

    def update(self, results, chunk_count):
        logging.info(f"Updating results. Chunk count: {chunk_count}, Matches: {len(results)}.")
        self.results.extend(results)
        self.total_count += chunk_count
        self.config.found_flag["found"] += len(results)
        self.summary_log["total_count"] += chunk_count
        self.summary_log["pwned"].extend(results)

    def finalize_summary(self):
        self.summary_log["elapsed_time"] = time.time() - self.config.start_time
        if self.config.found_flag["found"] == 0:
            self.summary_log["message"] = "No match found in word list. Program terminated."
        elif self.config.found_flag["found"] < self.config.found_flag["goal"]:
            self.summary_log["message"] = (
                f"{self.config.found_flag['found']} of {self.config.found_flag['goal']} matches found."
            )
        else:
            self.summary_log["message"] = (
                f"{self.config.found_flag['found']} matches found. All goals met!"
            )
        display_summary(self.config.found_flag, self.summary_log)