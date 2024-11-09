import os
import time
from multiprocessing import Manager
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm

from utils.file_utils import get_wordlist_length, load_wordlist, load_target
from utils.hash_utils import crack_chunk_wrapper
from utils.interface import get_command_line_args, display_summary

PASSWORD_LIST = "refs/dictionary_eng.txt"
COLOR = "\033[0;35m" # Purple
GREEN = "\033[92m"  # Bright green text
RESET = "\033[0m"

def process_future_result(future, flags):
    """Process the result of a completed future."""
    try:
        # Attempt to retrieve the result of the future
        result, chunk_count = future.result()
        # print("Future result retrieved successfully.")  # Debug statement

        if result:  # Check if a match was found
            flags["found"] = True  # Set flag to stop other processes
            print(f"\n{GREEN}Password match found -->> {RESET}{result}")
            return True, chunk_count  # Indicate that a match was found

    except Exception as e:
        # Print the exception along with the traceback to locate the exact problem
        import traceback
        print(f"Error encountered in process_future_result: {e}")
        traceback.print_exc()
    
    # Indicate that no match was found if no exceptions were raised
    return False, chunk_count  # No match found

def main():
    start_time = time.time()

    args = get_command_line_args()
    hash_string = load_target(args)

    num_cores = os.cpu_count()
    cpu_workers = num_cores
    batch_size = 1000
    max_in_flight_futures = num_cores * 2  # Control the number of concurrent tasks

    # Manager for multiprocessing, creating an Event "found_flag" for password match status.
    manager = Manager()
    flags = manager.dict(found=False, summary=False, start=start_time, end=None)

    total_count = 0  # Track the total count
    wordlist_length = get_wordlist_length(PASSWORD_LIST)
    total_batches = (wordlist_length // batch_size) + 1

    # Initialize ProcessPoolExecutor to utilize 'num_workers' for hash processing.
    with ProcessPoolExecutor(max_workers=cpu_workers) as process_executor:
        futures = []  # List to store 'future' instances of each password-checking task.

        for chunk in tqdm(load_wordlist(PASSWORD_LIST, batch_size), 
                          desc=f"{COLOR}Batch Processing{RESET}", total=total_batches, 
                          smoothing=1, ncols=100, leave=False, ascii=True
            ):
            if flags["found"]:
                break

            # Submit each chunk to ProcessPoolExecutor directly
            future = process_executor.submit(crack_chunk_wrapper, hash_string, chunk, flags)
            futures.append(future)

            # If we have reached the limit of concurrent futures, wait for one to complete
            if len(futures) >= max_in_flight_futures:
                # Wait for one of the futures to complete before adding more
                for completed_future in as_completed(futures):
                    match_found, chunk_count = process_future_result(completed_future, flags)
                    total_count += chunk_count # Accumulate counts

                    if match_found and not flags["summary"]:
                        flags["message"] = "Match found and program terminated.\n"
                        flags["end"] = time.time()
                        display_summary(cpu_workers, max_in_flight_futures, batch_size, flags, total_count)
                        return  # Exit immediately if a match is found

                    # Clean up completed futures to maintain the limit
                    futures = [f for f in futures if not f.done()]
                    break  # Exit after processing one completed future to keep submitting new chunks

        # Handle any remaining futures after loading all chunks
        for future in as_completed(futures):
            match_found, chunk_count = process_future_result(future, flags)
            total_count += chunk_count # Accumulate remaining futures counts

            if match_found and not flags["summary"]:
                flags["message"] = "Match found and program terminated.\n"
                flags["end"] = time.time()
                display_summary(cpu_workers, max_in_flight_futures, batch_size, flags, total_count)
                return

    if not flags["found"]:  # No password match found.
        flags["message"] = "No match found in word list. Program terminated.\n"
        flags["end"] = time.time()
        display_summary(cpu_workers, max_in_flight_futures, batch_size, flags, total_count)

if __name__ == "__main__":
    main()
