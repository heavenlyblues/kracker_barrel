from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager
import os, time
from pathlib import Path
from tqdm import tqdm
from utils.file_io import get_number_of_passwords, yield_password_batches, load_target_hash
from utils.hash_handler import crack_chunk_wrapper
from utils.reporter import display_summary, blinking_text, PURPLE, GREEN, LIGHT_YELLOW, RESET


class Kracker:
    def __init__(self, args):
        self.operation = args.operation
        self.target_file = Path ("data") / args.target_file
        self.hash_type = args.hash_type
        self.path_to_passwords = Path("refs") / "rockyou.txt"
        self.batch_size = 2000
        self.manager = Manager()
        self.start_time = time.time()
        self.hash_digest_with_metadata = load_target_hash(self.target_file)
        self.goal = len(self.hash_digest_with_metadata)
        self.found_flag = self.manager.dict(found=0, goal=self.goal)  # Global found_flag for stopping on goal match
        self.summary_log = self.initialize_summary_log()


    def __str__(self):
        return (
            f"\n{PURPLE}Kracker Configuration:{RESET}\n"
            f"  Operation: {self.operation}\n"
            f"  Input file: {self.target_file}\n"
            f"  Hash type: {self.hash_type}\n"
            f"  Path to passwords: {self.path_to_passwords}\n"
            f"  Batch size: {self.batch_size}\n"
        )


    def initialize_summary_log(self):
        number_of_passwords = get_number_of_passwords(self.path_to_passwords)
        total_batches = (number_of_passwords // self.batch_size) + 1
        return {
            "operation": self.operation,
            "hash_type": self.hash_type,
            "file_scanned": str(self.path_to_passwords.stem),
            "workers": os.cpu_count(),
            "batches": total_batches,
            "batch_size": self.batch_size,
            "items": number_of_passwords,
            "total_count": 0,
            "pwned": []
        }


    def run(self):
        """Main loop to process password batches and handle matches."""
        print(self)  # Calls the __str__ method to print the configuration
        try:
            with ProcessPoolExecutor(max_workers=self.summary_log["workers"]) as executor:
                batch_generator = yield_password_batches(self.path_to_passwords, self.batch_size)
                futures = []  # Queue to hold active Future objects
                preload_limit = self.summary_log["workers"] * 3

                print(f"{LIGHT_YELLOW}Starting preloading...{RESET}")
                blinking_text("Preloading batches...", duration=5)
                print("Done!\n")

                # Initialize tqdm with total number of batches
                with tqdm(desc=f"{PURPLE}Batch Processing{RESET}", 
                          total=self.summary_log["batches"], smoothing=1, 
                          ncols=100, leave=False, ascii=True) as progress_bar:

                    #  Submit batches to crack chunk and collect results in futures
                    for _ in range(preload_limit):
                        try:
                            chunk = next(batch_generator)
                            future = executor.submit(crack_chunk_wrapper, self.hash_type, 
                                                     self.hash_digest_with_metadata, chunk, 
                                                     self.found_flag)
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
                                    self.final_summary()
                                    return  # Exit immediately

                                # Dynamically preload new batches as space frees up
                                if len(futures) < preload_limit:
                                    try:
                                        chunk = next(batch_generator)
                                        new_future = executor.submit(crack_chunk_wrapper, self.hash_type, 
                                                                     self.hash_digest_with_metadata, chunk, 
                                                                     self.found_flag)
                                        futures.append(new_future)
                                    except StopIteration: # Generator raises a StopIteration exception
                                        pass  # No more batches to load
                            except Exception as e:
                                print(f"Error processing future: {e}")
                            finally:
                                futures.remove(future)
            self.final_summary()

        except KeyboardInterrupt:
            self.found_flag["found"] = -1
            self.summary_log["message"] = "Process interrupted. Partial summary_log displayed."
            self.summary_log["elapsed_time"] = time.time() - self.start_time
            display_summary(self.found_flag, self.summary_log)

    # Process the resluts from completed futures
    def process_task_result(self, task_result):
        """Process the result of a completed future."""
        try:
            pwned_pwd, chunk_count = task_result.result()
            self.summary_log["total_count"] += chunk_count

            if pwned_pwd:
                self.summary_log["pwned"].append(pwned_pwd)  # Append all matched passwords

                # Increment found_flag every time a match is found
                self.found_flag["found"] += 1
                tqdm.write(f"{GREEN}[MATCH] Password found: {pwned_pwd}{RESET}")

                return True, chunk_count
        except Exception as e:
            import traceback
            print(f"Error in process_task_result: {e}")
            pwned_pwd, chunk_count = False, 0 
            traceback.print_exc()
        
        return False, chunk_count


    def final_summary(self):
        """Display final summary after processing is completed."""
        if self.found_flag["found"] == 0:
            self.summary_log["message"] = (
                "No match found in word list. Program terminated."
            )

        elif self.found_flag["found"] < self.found_flag["goal"]:
            self.summary_log["message"] = (
                f"{self.found_flag['found']} of {self.found_flag['goal']} "
                "match(es) found in word list. Program terminated."
            )

        elif self.found_flag["found"] >= self.found_flag["goal"]:
            self.summary_log["message"] = (
                f"{self.found_flag['found']} of {self.found_flag['goal']} "
                "match(es) found in word list."
            )

        self.summary_log["elapsed_time"] = time.time() - self.start_time
        display_summary(self.found_flag, self.summary_log)