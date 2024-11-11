import os
import time
from multiprocessing import Manager
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm
from utils.file_utils import get_number_of_passwords, yield_password_batches, load_target_hash
from utils.hash_utils import crack_chunk_wrapper
from utils.interface import get_command_line_args, display_exit_summary, PURPLE, RESET


class Cracker:
    def __init__(self, path_to_passwords, batch_size):
        self.path_to_passwords = path_to_passwords
        self.batch_size = batch_size
        self.manager = Manager()
        self.found_flag = self.manager.dict(found=1)  # Global found_flag for stopping on match
        self.total_count = 0  # Track the total count
        self.message = ""
        self.start_time = time.time()
        self.args = get_command_line_args()
        self.hash_digest_with_metadata = load_target_hash(self.args)
        self.exit_summary = self.initialize_exit_summary()
    
    def initialize_exit_summary(self):
        number_of_passwords = get_number_of_passwords(self.path_to_passwords)
        total_batches = (number_of_passwords // self.batch_size) + 1
        return {
            "workers": os.cpu_count(),
            "batches": total_batches,
            "batch_size": self.batch_size,
            "items": number_of_passwords,
            "message": self.message
        }

    def process_future_result(self, future):
        """Process the result of a completed future."""
        try:
            result, chunk_count = future.result()
            if result:
                self.found_flag["found"] = 0
                return True, chunk_count, result
        except Exception as e:
            import traceback
            print(f"Error in process_future_result: {e}")
            traceback.print_exc()
        return False, chunk_count, None

    def futures_handler(self, future):
        match_found, chunk_count, cracked_password = self.process_future_result(future)
        self.total_count += chunk_count

        if match_found:
            self.message = "Match found and program terminated."
            total_time = time.time() - self.start_time
            display_exit_summary(self.found_flag, self.exit_summary, self.message, self.total_count, total_time, cracked_password)
            return True
        return False

    def run(self):
        try:
            with ProcessPoolExecutor(max_workers=self.exit_summary["workers"]) as executor:
                futures = []
                for chunk in tqdm(yield_password_batches(self.path_to_passwords, self.batch_size), 
                                  desc=f"{PURPLE}Batch Processing{RESET}", 
                                  total=self.exit_summary["batches"], smoothing=1, ncols=100, leave=False, ascii=True):
                    if self.found_flag["found"] == 0:
                        break

                    future = executor.submit(crack_chunk_wrapper, self.hash_digest_with_metadata, chunk, self.found_flag)
                    futures.append(future)

                    if len(futures) >= self.exit_summary["workers"] * 2:
                        for future in as_completed(futures):
                            if self.futures_handler(future):
                                return  # Exit if a match is found
                            futures = [f for f in futures if not f.done()]
                            break

                for future in as_completed(futures):
                    if self.futures_handler(future):
                        return

        except KeyboardInterrupt:
            self.found_flag["found"] = 2
            self.message = "Process interrupted. Partial exit_summary displayed."
            total_time = time.time() - self.start_time
            display_exit_summary(self.found_flag, self.exit_summary, self.message, self.total_count, total_time)
        
        finally:
            if self.found_flag["found"] == 1:
                self.message = "No match found in word list. Program terminated."
                total_time = time.time() - self.start_time
                display_exit_summary(self.found_flag, self.exit_summary, self.message, self.total_count, total_time)