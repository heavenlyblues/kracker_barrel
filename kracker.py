import os
import time
from pathlib import Path
from multiprocessing import Manager, shared_memory
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm
from utils.file_utils import get_number_of_passwords, yield_password_batches, load_target_hash
from utils.hash_utils import crack_chunk_wrapper
from utils.interface import display_summary, PURPLE, RESET


class Kracker:
    def __init__(self, target_file, path_to_passwords, batch_size):
        self.path_to_passwords = path_to_passwords
        self.batch_size = batch_size
        self.manager = Manager()
        self.start_time = time.time()
        self.target_file = Path ("data") / target_file
        self.hash_digest_with_metadata = load_target_hash(self.target_file)
        self.goal = len(self.hash_digest_with_metadata)
        self.found_flag = self.manager.dict(found=0, goal=self.goal)  # Global found_flag for stopping on goal match
        self.summary_log = self.initialize_summary_log()


    def initialize_summary_log(self):
        number_of_passwords = get_number_of_passwords(self.path_to_passwords)
        total_batches = (number_of_passwords // self.batch_size) + 1
        return {
            "file_scanned": str(self.path_to_passwords.stem),
            "workers": os.cpu_count(),
            "batches": total_batches,
            "batch_size": self.batch_size,
            "items": number_of_passwords,
            "total_count": 0,
            "pwned": []
        }


    def process_task_result(self, task_result):
        """Process the result of a completed future."""
        try:
            pwned_pwd, chunk_count = task_result.result()
            self.summary_log["total_count"] += chunk_count

            if pwned_pwd:
                self.summary_log["pwned"].append(pwned_pwd)  # Append all matched passwords

                # Increment found_flag every time a match is found
                self.found_flag["found"] += 1

                return True, chunk_count
        except Exception as e:
            import traceback
            print(f"Error in process_task_result: {e}")
            pwned_pwd, chunk_count = False, 0 
            traceback.print_exc()
        
        return False, chunk_count


    def run(self):
        """Main loop to process password batches and handle matches."""
        try:
            with ProcessPoolExecutor(max_workers=self.summary_log["workers"]) as executor:
                batch_generator = yield_password_batches(self.path_to_passwords, self.batch_size)
                futures = []  # Queue to hold active Future objects
                preload_limit = self.summary_log["workers"] * 3  # Preload twice the number of workers
                                    # Preload initial batches into the queue
                print("Preloading initial batches...")
                # Initialize tqdm with total number of batches
                with tqdm(
                    desc=f"{PURPLE}Batch Processing{RESET}",
                    total=self.summary_log["batches"],
                    smoothing=1,
                    ncols=100,
                    leave=True,
                    ascii=True,
                ) as pbar:

                    for _ in range(preload_limit):
                        try:
                            chunk = next(batch_generator)
                            future = executor.submit(crack_chunk_wrapper, self.hash_digest_with_metadata, chunk, self.found_flag)
                            futures.append(future)
                        except StopIteration:
                            break  # No more batches to preload

                    # Process futures dynamically as they complete
                    while futures:
                        for future in as_completed(futures):
                            try:
                                # Send the Future to process_task_result
                                self.process_task_result(future)

                                # Update the progress bar
                                pbar.update(1)

                                # Stop if the required number of matches is found
                                if self.found_flag["found"] == self.found_flag["goal"]:
                                    self.final_summary()
                                    return  # Exit immediately

                                # Dynamically preload new batches as space frees up
                                if len(futures) < preload_limit:
                                    try:
                                        chunk = next(batch_generator)
                                        new_future = executor.submit(crack_chunk_wrapper, self.hash_digest_with_metadata, chunk, self.found_flag)
                                        futures.append(new_future)
                                    except StopIteration:
                                        pass  # No more batches to load
                            except Exception as e:
                                print(f"Error processing future: {e}")
                            finally:
                                # Remove completed future
                                futures.remove(future)
            self.final_summary()

        except KeyboardInterrupt:
            self.found_flag["found"] = -1
            self.summary_log["message"] = "Process interrupted. Partial summary_log displayed."
            self.summary_log["elapsed_time"] = time.time() - self.start_time
            display_summary(self.found_flag, self.summary_log)


    def final_summary(self):
        """Display final summary after processing is completed."""
        if self.found_flag["found"] == 0:
            self.summary_log["message"] = "No match found in word list. Program terminated."
        elif self.found_flag["found"] < self.found_flag["goal"]:
            self.summary_log["message"] = f"{self.found_flag['found']} match(es) found in word list. Program terminated."
        elif self.found_flag["found"] >= self.found_flag["goal"]:
            self.summary_log["message"] = f"{self.found_flag['found']} match(es) found in word list."
        self.summary_log["elapsed_time"] = time.time() - self.start_time
        display_summary(self.found_flag, self.summary_log)