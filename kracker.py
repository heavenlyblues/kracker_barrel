import os
import time
from pathlib import Path
from multiprocessing import Manager
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
        self.found_flag = self.manager.dict(found=1)  # Global found_flag for stopping on match
        self.start_time = time.time()
        self.target_file = Path ("data") / target_file
        self.hash_digest_with_metadata = load_target_hash(self.target_file)
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
            "total_count": 0
        }

    def process_task_result(self, task_result):
        """Process the result of a completed future."""
        try:
            result, chunk_count = task_result.result()
            if result:
                self.found_flag["found"] = 0
                self.summary_log["password"] = result
                return True, chunk_count
        except Exception as e:
            import traceback
            print(f"Error in process_task_result: {e}")
            result, chunk_count = False, 0 
            traceback.print_exc()
        return False, chunk_count

    def handle_task_result(self, task_result):
        match_found, chunk_count = self.process_task_result(task_result)
        self.summary_log["total_count"] += chunk_count

        if match_found:
            self.summary_log["message"] = "Match found and program terminated."
            self.summary_log["elapsed_time"] = time.time() - self.start_time
            display_summary(self.found_flag, self.summary_log)
            return True
        return False

    def run(self):
        try:
            with ProcessPoolExecutor(max_workers=self.summary_log["workers"]) as executor:
                password_batch_tasks = []
                # Submit password batches as tasks to the executor
                for chunk in tqdm(yield_password_batches(self.path_to_passwords, self.batch_size), 
                                desc=f"{PURPLE}Batch Processing{RESET}", 
                                total=self.summary_log["batches"], smoothing=1, ncols=100, leave=False, ascii=True):
                    if self.found_flag["found"] == 0:
                        break
                    
                    # Submit each password batch for processing
                    task_result = executor.submit(crack_chunk_wrapper, self.hash_digest_with_metadata, chunk, self.found_flag)
                    password_batch_tasks.append(task_result)

                    # Handle completed tasks and clean up finished futures
                    if len(password_batch_tasks) >= self.summary_log["workers"] * 2:
                        for task_result in as_completed(password_batch_tasks):
                            if self.handle_task_result(task_result):
                                return  # Exit if a match is found
                            password_batch_tasks = [f for f in password_batch_tasks if not f.done()]
                            break

                # Final pass to process any remaining tasks
                for task_result in as_completed(password_batch_tasks):
                    if self.handle_task_result(task_result):
                        return

        except KeyboardInterrupt:
            self.found_flag["found"] = 2
            self.summary_log["message"] = "Process interrupted. Partial summary_log displayed."
            self.summary_log["elapsed_time"] = time.time() - self.start_time
            display_summary(self.found_flag, self.summary_log)
        
        finally:
            if self.found_flag["found"] == 1:
                self.summary_log["message"] = "No match found in word list. Program terminated."
                self.summary_log["elapsed_time"] = time.time() - self.start_time
                display_summary(self.found_flag, self.summary_log)