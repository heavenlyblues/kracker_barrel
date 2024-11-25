import atexit
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager, shared_memory
import numpy as np
import os, platform, time
from pathlib import Path
from tqdm import tqdm
from core.hash_handler import HashHandler
from core.brut_gen import generate_brute_candidates, yield_brute_batches, get_brute_count
from core.mask_gen import generate_mask_candidates, yield_maskbased_batches, get_mask_count
from utils.file_io import get_number_of_passwords, yield_dictionary_batches, load_target_hash
from utils.reporter import display_summary, PURPLE, GREEN, LIGHT_YELLOW, DIM, RESET


class Kracker:
    def __init__(self, args):
        self.memory_cleaned = False
        self.operation = args.operation # dict, brut, mask, rule
        self.target_file = Path ("data") / args.target_file
        self.hash_digest_with_metadata = load_target_hash(self.target_file) # List of hashes to crack
        self.hash_type = self.detect_hash_type() # argon, bcrypt, pbkfd2, scrypt, ntlm, md5, sha256, sha512
        self.path_to_passwords = Path("refs") / args.password_list if args.password_list else None
        
        self.mask_pattern = args.pattern # Mask-based attack
        self.custom_strings = args.custom if args.custom else None # Mask-based custom string to append
        self.brute_settings = dict(charset=args.charset, min=args.min, max=args.max)

        self.manager = Manager()
        self.start_time = time.time()
        self.goal = len(self.hash_digest_with_metadata) # Number of hashes in file to crack
        self.found_flag = self.manager.dict(found=0, goal=self.goal)  # Global found_flag for stopping on goal match
        
        self.max_password_size = 128  # Maximum password length in bytes
        self.batch_size = 2000  # Adjust batch size for performance
        self.batch_generator = None

        # Calculate shared memory size (batch size * max password length in bytes)
        self.shared_memory_size = self.max_password_size * self.batch_size

        # Create shared memory block
        self.shared_mem = shared_memory.SharedMemory(create=True, size=self.shared_memory_size)

        # Map shared memory to a NumPy array for easy handling
        self.shared_array = np.ndarray((self.batch_size, self.max_password_size), dtype=np.uint8, buffer=self.shared_mem.buf)
        
        atexit.register(self.cleanup_shared_memory_atexit)

        self.hash_handler = self.initialize_hash_handler()
        self.summary_log = self.initialize_summary_log()

    def __del__(self):
        try:
            if hasattr(self, "memory_cleaned") and not self.memory_cleaned:
                self.cleanup_shared_memory()
        except Exception as e:
            print(f"Error during object deletion: {e}")

    def cleanup_shared_memory(self):
        if not self.memory_cleaned and hasattr(self, "shared_mem") and self.shared_mem:
            try:
                self.shared_mem.close()
                self.shared_mem.unlink()
                self.memory_cleaned = True
            except FileNotFoundError:
                print("Shared memory already unlinked.")
            except Exception as e:
                print(f"Error cleaning up shared memory: {e}")

    def cleanup_shared_memory_atexit(self):
        try:
            self.cleanup_shared_memory()
        except Exception as e:
            print(f"Error during shared memory cleanup at exit: {e}")

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


    def initialize_hash_handler(self):
        handlers = {
            "argon": HashHandler.Argon2Handler,
            "scrypt": HashHandler.ScryptHandler,
            "pbkdf2": HashHandler.PBKDF2Handler,
            "bcrypt": HashHandler.BcryptHandler,
            "ntlm": HashHandler.NTLMHandler,
            "md5": HashHandler.MD5Handler,
            "sha256": HashHandler.SHA256Handler,
            "sha512": HashHandler.SHA512Handler,
        }
        try:
            handler_class = handlers.get(self.hash_type)
            if not handler_class:
                raise ValueError(f"No handler found for hash type: {self.hash_type}")
            return handler_class(self.hash_digest_with_metadata)  # Pass metadata if required
        except ValueError as e:
            raise ValueError(f"Error determining hash type or handler: {e}")


    def __str__(self):
        return (
            f"\n{PURPLE}Kracker Configuration:{RESET}\n"
            f"  Operation: {self.operation}\n"
            f"  Target: {self.target_file}\n"
            f"  Hash type: {self.hash_type}\n"
            f"  Password list: {self.path_to_passwords}\n"
            f"  Batch size: {self.batch_size}\n"
            f"  Workers: {self.summary_log["workers"]}\n"
        )


    def initialize_summary_log(self):
        if self.operation == "dict":
            number_of_passwords = get_number_of_passwords(self.path_to_passwords)
        elif self.operation == "brut":
            number_of_passwords = get_brute_count(self.brute_settings)
        elif self.operation == "mask":
            number_of_passwords = get_mask_count(self.mask_pattern, self.custom_strings)
        elif self.operation == "rule":
            number_of_passwords = 1

        
        total_batches = (number_of_passwords // self.batch_size) + 1
        
        return {
            "operation": self.operation,
            "input_file": self.target_file,
            "hash_type": self.hash_type,
            "file_scanned": self.path_to_passwords,
            "workers": os.cpu_count(),
            "batches": total_batches,
            "batch_size": self.batch_size,
            "items": number_of_passwords,
            "total_count": 0,
            "pwned": []
        }


    def initialize_batch_generator(self):
        if self.operation == "dict":
            self.batch_generator = yield_dictionary_batches(self.path_to_passwords, self.batch_size)
        elif self.operation == "brut":
            generator = generate_brute_candidates(self.brute_settings)
            self.batch_generator = yield_brute_batches(generator, self.batch_size)
        elif self.operation == "mask":
            generator = generate_mask_candidates(self.mask_pattern, self.custom_strings)
            self.batch_generator = yield_maskbased_batches(generator, self.batch_size)
        elif self.operation == "rule":
            raise NotImplementedError("Rule-based attack is not implemented.")
        print(f"Batch generator initialized: {self.batch_generator}")

    # def init_worker(worker_id):
    #     global WORKER_ID
    #     WORKER_ID = worker_id  # Store worker ID in global variable

    def write_to_shared_memory(self, batch):
        print(f"Writing batch of size {len(batch)} to shared memory")
        for i, password in enumerate(batch):
            # Convert password to bytes and store it in the shared array    
            # print(f"Worker {worker_id} processing password index {i}: {password}")
            self.shared_array[i, :len(password)] = np.frombuffer(password, dtype=np.uint8)
            self.shared_array[i, len(password):] = 0  # Zero out the remaining space

        # Clear any unused rows in the shared memory
        for i in range(len(batch), self.batch_size):
            self.shared_array[i, :] = 0

        # Debug the written data
        print(f"Shared memory contents after writing batch:")
        print(self.shared_array[:len(batch)])

    def run(self):
        """Main loop to process password batches and handle matches."""
        print(self)  # Calls the __str__ method to print the configuration

        atexit.register(self.cleanup_shared_memory_atexit)
        
        try:
            with ProcessPoolExecutor(max_workers=self.summary_log["workers"]) as executor:
                self.initialize_batch_generator()

                futures = []  # Queue to hold active Future objects
                preload_limit = self.summary_log["workers"] * 3
                print(f"{LIGHT_YELLOW}Starting batch preloading...{RESET}", end=" ")
                print(f"{DIM}Done!{RESET}")

                # Initialize tqdm with total number of batches
                with tqdm(
                    desc=f"{PURPLE}Batch Processing{RESET}", 
                    total=self.summary_log["batches"], mininterval=0.1, smoothing=0.1, 
                    ncols=100, leave=True, ascii=True
                ) as progress_bar:

                    #  Submit batches to crack chunk and collect results in futures
                    for _ in range(preload_limit):
                        try:
                            batch = next(self.batch_generator)
                            print(f"Preloading batch: {batch[:5]}...")  # Debug log
                            # Write batch to shared memory
                            self.write_to_shared_memory(batch)
                            

                            future = executor.submit(
                                self.hash_handler.crack_chunk_wrapper,
                                self.shared_mem.name, 
                                self.batch_size, self.max_password_size, 
                                self.found_flag
                            )
                            futures.append(future)
                        except StopIteration:  # Once batches are consumed, generator raises a StopIteration exception
                            break  # No more batches to preload

                    # Process futures dynamically as they complete
                    while futures:
                        for future in as_completed(futures):
                            try:
                                self.process_task_result(future)

                                progress_bar.update(1) # Update the progress bar

                                # Stop if all the target hashes are matched 
                                if self.found_flag["found"] == self.found_flag["goal"]:
                                    progress_bar.close()  # Ensure progress bar closes cleanly
                                    self.final_summary()
                                    return  # Exit immediately

                                # Dynamically preload new batches as space frees up
                                if len(futures) < preload_limit:
                                    try:
                                        batch = next(self.batch_generator)
                                        print(f"Submitting batch: {len(batch)} passwords")
                                        self.write_to_shared_memory(batch)

                                        new_future = executor.submit(
                                            self.hash_handler.crack_chunk_wrapper,
                                            self.shared_mem.name, self.batch_size, 
                                            self.max_password_size, 
                                            self.found_flag
                                        )
                                        futures.append(new_future)
                                    except StopIteration: # Generator raises a StopIteration exception
                                        pass  # No more batches to load
                            except Exception as e:
                                print(f"Error processing future: {e}")
                            finally:
                                futures.remove(future)
                    progress_bar.close()  # Ensure progress bar closes cleanly
            self.final_summary()

        except KeyboardInterrupt:
            self.found_flag["found"] = -1
            self.summary_log["message"] = "Process interrupted. Partial summary_log displayed."
            self.summary_log["elapsed_time"] = time.time() - self.start_time
            display_summary(self.found_flag, self.summary_log)
        
        finally:
            # Ensure shared memory cleanup
            self.cleanup_shared_memory()


    # Process the resluts from completed futures
    def process_task_result(self, task_result):
        """Process the result of a completed future."""
        try:
            results, chunk_count = task_result.result()  # Expecting a tuple
            self.summary_log["total_count"] += chunk_count

            # Process all matches in the results list
            for pwned_pwd in results:
                self.summary_log["pwned"].append(pwned_pwd)
                self.found_flag["found"] += 1
                tqdm.write(f"{GREEN}[MATCH] Password found: {pwned_pwd}{RESET}")

            # # If no matches were found
            # if not results:
            #     tqdm.write(f"{LIGHT_YELLOW}[INFO] No matches found in this chunk.{RESET}")

            return True, chunk_count
        except Exception as e:
            import traceback
            print(f"Error in process_task_result: {e}")
            pwned_pwd, chunk_count = False, 0 
            traceback.print_exc()
        
        return False, chunk_count


    def final_summary(self):
        """Display final summary after processing is completed."""
        # Retrieve hash parameters
        self.summary_log["hash_parameters"] = self.hash_handler.log_parameters()

        # Construct the final message based on results
        if self.found_flag["found"] == 0:
            self.summary_log["message"] = (
                "No match found in word list. Program terminated."
            )
        elif self.found_flag["found"] < self.found_flag["goal"]:
            self.summary_log["message"] = (
                f"{self.found_flag['found']} of {self.found_flag['goal']} "
                "match(es) found in word list. Program terminated."
            )
        else:
            self.summary_log["message"] = (
                f"{self.found_flag['found']} of {self.found_flag['goal']} "
                "match(es) found in word list."
            )

        self.summary_log["elapsed_time"] = time.time() - self.start_time
        display_summary(self.found_flag, self.summary_log)