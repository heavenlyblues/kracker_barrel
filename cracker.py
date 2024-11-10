import os
import time
from multiprocessing import Manager
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm
from utils.file_utils import get_wordlist_length, load_wordlist, load_target
from utils.hash_utils import crack_chunk_wrapper
from utils.interface import get_command_line_args, display_summary, PURPLE, RESET


class Cracker:
    def __init__(self, password_list, batch_size):
        self.password_list = password_list
        self.batch_size = batch_size
        self.manager = Manager()
        self.flag = self.manager.dict(found=1)  # Global flag for stopping on match
        self.total_count = 0  # Track the total count
        self.start_time = time.time()
        self.args = get_command_line_args()
        self.hash_string = load_target(self.args)
        self.summary = self.initialize_summary()
    
    def initialize_summary(self):
        wordlist_length = get_wordlist_length(self.password_list)
        total_batches = (wordlist_length // self.batch_size) + 1
        return {
            "workers": os.cpu_count(),
            "batches": total_batches,
            "batch_size": self.batch_size,
            "items": wordlist_length
        }

    def process_future_result(self, future):
        """Process the result of a completed future."""
        try:
            result, chunk_count = future.result()
            if result:
                self.flag["found"] = 0
                return True, chunk_count, result
        except Exception as e:
            import traceback
            print(f"Error in process_future_result: {e}")
            traceback.print_exc()
        return False, chunk_count, None

    def futures_handler(self, future):
        match_found, chunk_count, password = self.process_future_result(future)
        self.total_count += chunk_count

        if match_found:
            message = "Match found and program terminated."
            total_time = time.time() - self.start_time
            display_summary(self.flag, self.summary, message, self.total_count, total_time, password)
            return True
        return False

    def run(self):
        try:
            with ProcessPoolExecutor(max_workers=self.summary["workers"]) as executor:
                futures = []
                for chunk in tqdm(load_wordlist(self.password_list, self.batch_size), 
                                  desc=f"{PURPLE}Batch Processing{RESET}", 
                                  total=self.summary["batches"], smoothing=1, ncols=100, leave=False, ascii=True):
                    if self.flag["found"] == 0:
                        break

                    future = executor.submit(crack_chunk_wrapper, self.hash_string, chunk, self.flag)
                    futures.append(future)

                    if len(futures) >= self.summary["workers"] * 2:
                        for future in as_completed(futures):
                            if self.futures_handler(future):
                                return  # Exit if a match is found
                            futures = [f for f in futures if not f.done()]
                            break

                for future in as_completed(futures):
                    if self.futures_handler(future):
                        return

        except KeyboardInterrupt:
            self.flag["found"] = 2
            message = "Process interrupted. Partial summary displayed."
            total_time = time.time() - self.start_time
            display_summary(self.flag, self.summary, message, self.total_count, total_time)
        
        finally:
            if self.flag["found"] == 1:
                message = "No match found in word list. Program terminated."
                total_time = time.time() - self.start_time
                display_summary(self.flag, self.summary, message, self.total_count, total_time)