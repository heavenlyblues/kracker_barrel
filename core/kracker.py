from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager
from multiprocessing.shared_memory import ShareableList
from multiprocessing.managers import SharedMemoryManager
import os, time
from pathlib import Path
from tqdm import tqdm
from core.hash_handler import crack_chunk
from core.brut_gen import generate_brute_candidates, yield_brute_batches, get_brute_count
from core.mask_gen import generate_mask_candidates, yield_maskbased_batches, get_mask_count
from utils.detector import HashTypeDetector
from utils.file_io import get_number_of_passwords, yield_dictionary_batches, validate_password_file, load_target_hash
from utils.reporter import display_summary, PURPLE, GREEN, LIGHT_YELLOW, DIM, RESET
# import pdb


class Kracker:
    def __init__(self, args):
        self.operation = args.operation # dict, brut, mask, rule
        self.target_file = Path ("data") / args.target_file
        self.hash_digest_with_metadata = load_target_hash(self.target_file) # List of hashes to crack
        self.path_to_passwords = Path("refs") / args.password_list if args.password_list else None
        self.mask_pattern = args.pattern # Mask-based attack
        self.custom_strings = args.custom if args.custom else None # Mask-based custom string to append
        self.brute_settings = dict(charset=args.charset, min=args.min, max=args.max)
        self.workers = os.cpu_count() - 1
        self.preload_limit = self.workers * 3
        self.batch_size = 5000  # Adjust batch size for performance
        
        # Detect and initialize hash handler
        self.hash_type = HashTypeDetector.detect(self.hash_digest_with_metadata)
        self.hash_handler = HashTypeDetector.initialize(self.hash_digest_with_metadata, self.hash_type)

        self.manager = Manager()
        self.start_time = time.time()
        self.goal = len(self.hash_digest_with_metadata) # Number of hashes in file to crack
        self.found_flag = self.manager.dict(found=0, goal=self.goal)  # Global found_flag for stopping on goal match


class BatchManager:
    def __init__(self, kracker):
        self.kracker = kracker
        self.batch_generator = None
        self.total_passwords = 0
        self.smm = SharedMemoryManager()
        self.smm.start()
        self.max_batches = 0
        self.rem_batches = 0


    def initialize_batch_generator(self):
        if self.kracker.operation == "dict":
            invalid_lines = validate_password_file(self.kracker.path_to_passwords)
            if invalid_lines:
                print(f"Invalid lines detected: {invalid_lines}")
            self.batch_generator = yield_dictionary_batches(self.kracker.path_to_passwords, self.kracker.batch_size)
            self.total_passwords = get_number_of_passwords(self.kracker.path_to_passwords)

        elif self.kracker.operation == "brut":
            generator = generate_brute_candidates(self.kracker.brute_settings)
            self.batch_generator = yield_brute_batches(generator, self.kracker.batch_size)

        elif self.kracker.operation == "mask":
            generator = generate_mask_candidates(self.mask_pattern, self.kracker.custom_strings)
            self.batch_generator = yield_maskbased_batches(generator, self.kracker.batch_size)

        elif self.kracker.operation == "rule":
            pass

        self.max_batches = -(-self.total_passwords // self.kracker.batch_size)
        self.rem_batches = self.max_batches


    def preload_batches(self, limit):
        """ Preload a specified number of batches into a single ShareableList.
            Called by ProcessPoolExecutor
        """
        shared_batches = []
        max_password_length = 0

        for _ in range(limit):
            try:
                batch = next(self.batch_generator)
                max_password_length = max(max_password_length, *(len(password) for password in batch))
                shared_batch = self.smm.ShareableList(batch)  # Store each batch directly
                shared_batches.append(shared_batch.shm.name)  # Store shared memory names
            except StopIteration:
                print("No more batches to preload.")
                break

        self.shared_batches = self.smm.ShareableList(shared_batches)
        self.max_password_length = max_password_length
        self.rem_batches -= len(shared_batches)  # Update remaining batches
        # print(f"Preloaded {len(self.shared_batches)} batches.")


    def get_batch(self, index):
        """Retrieve and deserialize a batch from the ShareableList."""
        try:
            shared_name = self.shared_batches[index]
            shared_batch = ShareableList(name=shared_name)  # Access shared memory
            return list(shared_batch)  # Convert back to a Python list
        except IndexError:
            print(f"No batch found at index {index}.")
            return None


    def cleanup(self):
        """Release shared memory."""
        self.smm.shutdown()


class Workers:
    def __init__(self, kracker, batch_man, reporter):
        self.kracker = kracker
        self.batch_man = batch_man
        self.reporter = reporter  # Reporter instance for logging


    def run(self):
        """Main loop to process password batches and handle matches."""
        print(self.reporter)  # Calls the __str__ method to print the configuration
        self.batch_man.initialize_batch_generator()

        try:
            with ProcessPoolExecutor(max_workers=self.kracker.workers) as executor:
                self.batch_man.preload_batches(self.kracker.preload_limit)
                current_batches = len(self.batch_man.shared_batches)  # Get total batches from the ShareableList
                
                futures = []  # Queue to hold active Future objects
                current_batch_index = 0  # Start with the first batch

                print(f"{LIGHT_YELLOW}Starting batch preloading...{RESET}", end=" ")
                print(f"{DIM}Done!{RESET}")

                # Initialize tqdm with total number of batches
                with tqdm(desc=f"{PURPLE}Batch Processing{RESET}", 
                          total=self.batch_man.max_batches, 
                          mininterval=0.1, smoothing=0.1, 
                          ncols=100, leave=True, ascii=True) as progress_bar:

                    # Main processing loop
                    while futures or current_batch_index < current_batches or self.batch_man.rem_batches > 0:

                        while len(futures) < self.kracker.preload_limit and current_batch_index < current_batches:
                            # print(f"Submitting batch {current_batch_index}")
                            batch = self.batch_man.get_batch(current_batch_index)
                            # print(f"Batch {current_batch_index}: {batch}")
                            if batch is None:
                                break
                            future = executor.submit(
                                crack_chunk,
                                self.kracker.hash_type,
                                self.kracker.hash_digest_with_metadata,
                                batch, 
                                self.kracker.found_flag,
                            )
                            futures.append(future)
                            current_batch_index += 1

                        # Process completed futures
                        for future in as_completed(futures):
                            try:
                                self.process_task_result(future)
                                progress_bar.update(1)  # Update the progress bar

                                # Stop if all target hashes are matched
                                if self.kracker.found_flag["found"] == self.kracker.found_flag["goal"]:
                                    progress_bar.close()
                                    self.reporter.final_summary()
                                    return  # Exit immediately
                            except Exception as e:
                                print(f"Error processing future: {e}")
                            finally:
                                futures.remove(future)
                        
                        # Dynamically preload more batches if needed
                        if current_batch_index == current_batches and self.batch_man.rem_batches > 0:
                            self.batch_man.preload_batches(
                                min(self.kracker.preload_limit, self.batch_man.rem_batches)
                            )
                            current_batches = len(self.batch_man.shared_batches)
                            current_batch_index = 0  # Reset for the newly preloaded batches

                progress_bar.close()
            self.reporter.final_summary()

        except KeyboardInterrupt:
            self.kracker.found_flag["found"] = -1
            self.reporter.summary_log["message"] = "Process interrupted. Partial summary_log displayed."
            self.reporter.summary_log["elapsed_time"] = time.time() - self.kracker.start_time
            display_summary(self.kracker.found_flag, self.reporter.summary_log)

        finally:
            self.batch_man.cleanup()


    # Process the resluts from completed futures
    def process_task_result(self, task_result):
        """Process the result of a completed future."""
        try:
            results, chunk_count = task_result.result()  # Expecting a tuple
            self.reporter.summary_log["total_count"] += chunk_count

            # Process all matches in the results list
            for pwned_pwd in results:
                self.reporter.summary_log["pwned"].append(pwned_pwd)
                self.kracker.found_flag["found"] += 1
                tqdm.write(f"{GREEN}[MATCH] Password found: {pwned_pwd}{RESET}")

            return True, chunk_count
        except Exception as e:
            import traceback
            print(f"Error in process_task_result: {e}")
            pwned_pwd, chunk_count = False, 0 
            traceback.print_exc()
        
        return False, chunk_count


class Reporter:
    def __init__(self, kracker):
        self.kracker = kracker
        self.summary_log = self.initialize_summary_log()


    def __str__(self):
        return (
            f"\n{PURPLE}Kracker Configuration:{RESET}\n"
            f"  Operation: {self.kracker.operation}\n"
            f"  Target: {self.kracker.target_file}\n"
            f"  Hash type: {self.kracker.hash_type}\n"
            f"  Password list: {self.kracker.path_to_passwords}\n"
            f"  Batch size: {self.kracker.batch_size}\n"
            f"  Logical cores: {os.cpu_count()}\n"
            f"  Workers: {self.summary_log["workers"]}\n"
            f"  Process PID: {os.getpid()}\n"
            f"  Preload limit: {self.kracker.preload_limit}\n"
        )


    def initialize_summary_log(self):
        if self.kracker.operation == "dict":
            number_of_passwords = get_number_of_passwords(self.kracker.path_to_passwords)
        elif self.kracker.operation == "brut":
            number_of_passwords = get_brute_count(self.kracker.brute_settings)
        elif self.kracker.operation == "mask":
            number_of_passwords = get_mask_count(self.kracker.mask_pattern, self.kracker.custom_strings)
        elif self.kracker.operation == "rule":
            number_of_passwords = 1

        total_batches = (number_of_passwords // self.kracker.batch_size) + 1
        
        return {
            "operation": self.kracker.operation,
            "input_file": self.kracker.target_file,
            "hash_type": self.kracker.hash_type,
            "hash_parameters": None,
            "file_scanned": self.kracker.path_to_passwords,
            "workers": self.kracker.workers,
            "batches": total_batches,
            "batch_size": self.kracker.batch_size,
            "items": number_of_passwords,
            "total_count": 0,
            "pwned": []
        }


    def final_summary(self):
        """Display final summary after processing is completed."""
        # Retrieve hash parameters
        try:
            self.summary_log["hash_parameters"] = self.kracker.hash_handler.log_parameters()
        except AttributeError:
            self.summary_log["hash_parameters"] = "N/A"  # Default if no parameters are available

        # Construct the final message based on results
        if self.kracker.found_flag["found"] == 0:
            self.summary_log["message"] = (
                "No match found in word list. Program terminated."
            )
        elif self.kracker.found_flag["found"] < self.kracker.found_flag["goal"]:
            self.summary_log["message"] = (
                f"{self.kracker.found_flag['found']} of {self.kracker.found_flag['goal']} "
                "match(es) found in word list. Program terminated."
            )
        else:
            self.summary_log["message"] = (
                f"{self.kracker.found_flag['found']} of {self.kracker.found_flag['goal']} "
                "match(es) found in word list."
            )

        self.summary_log["elapsed_time"] = time.time() - self.kracker.start_time
        display_summary(self.kracker.found_flag, self.summary_log)