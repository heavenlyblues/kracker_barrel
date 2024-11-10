import os
import time
from multiprocessing import Manager
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm

from utils.file_utils import get_wordlist_length, load_wordlist, load_target
from utils.hash_utils import crack_chunk_wrapper
from utils.interface import get_command_line_args, display_summary, P, G, R, RESET

PASSWORD_LIST = "refs/dictionary_eng.txt"
BATCH_SIZE = 1000


def process_future_result(future, flags):
    """Process the result of a completed future."""
    try:
        result, chunk_count = future.result()

        if result:  # Check if a match was found
            flags["found"] = True  # Set flag to stop other processes
            return True, chunk_count, result  # Indicate that a match was found

    except Exception as e:
        # Print the exception along with the traceback to locate the exact problem
        import traceback
        print(f"Error encountered in process_future_result: {e}")
        traceback.print_exc()
    
    # Indicate that no match was found if no exceptions were raised
    return False, chunk_count, None  # No match found


def main():
    start_time = time.time()

    args = get_command_line_args()
    hash_string = load_target(args)

    num_cores = os.cpu_count()
    cpu_workers = num_cores
    batch_size = BATCH_SIZE
    max_in_flight_futures = num_cores * 2  # Control the number of concurrent tasks

    total_count = 0  # Track the total count
    wordlist_length = get_wordlist_length(PASSWORD_LIST)
    total_batches = (wordlist_length // batch_size) + 1
    summary = dict(workers=cpu_workers, batches=total_batches, 
                   batch_size=batch_size, items=wordlist_length)

    # Manager for multiprocessing, creating a "found_flag" for password match status.
    manager = Manager()
    flags = manager.dict(found=False)

    # Initialize ProcessPoolExecutor to utilize 'num_workers' for hash processing.
    with ProcessPoolExecutor(max_workers=cpu_workers) as process_executor:
        futures = []  # List to store 'future' instances of each password-checking task.

        for chunk in tqdm(load_wordlist(PASSWORD_LIST, batch_size), 
                          desc=f"{P}Batch Processing{RESET}", total=total_batches, 
                          smoothing=1, ncols=100, leave=False, ascii=True):
            
            if flags["found"]:
                break

            # Submit each chunk to ProcessPoolExecutor directly
            future = process_executor.submit(crack_chunk_wrapper, hash_string, chunk, flags)
            futures.append(future)

            # If we have reached the limit of concurrent futures, wait for one to complete
            if len(futures) >= max_in_flight_futures:
                # Wait for one of the futures to complete before adding more
                for completed_future in as_completed(futures):
                    match_found, chunk_count, password = process_future_result(completed_future, flags)
                    total_count += chunk_count # Accumulate counts

                    if match_found:
                        message = "Match found and program terminated."
                        total_time = time.time() - start_time
                        display_summary(summary, message, total_count, total_time, password)
                        return  # Exit immediately if a match is found

                    # Clean up completed futures to maintain the limit
                    futures = [f for f in futures if not f.done()]
                    break  # Exit after processing one completed future to keep submitting new chunks

        # Handle any remaining futures after loading all chunks
        for future in as_completed(futures):
            match_found, chunk_count, password = process_future_result(future, flags)
            total_count += chunk_count # Accumulate remaining futures counts

            if match_found:
                message = "Match found and program terminated."
                total_time = time.time() - start_time
                display_summary(summary, message, total_count, total_time, password)
                return

    if not flags["found"]:  # No password match found.
        message = "No match found in word list. Program terminated."
        total_time = time.time() - start_time
        display_summary(summary, message, total_count, total_time)

if __name__ == "__main__":
    main()
