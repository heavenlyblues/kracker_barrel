import os
import time
from multiprocessing import Manager
from concurrent.futures import ProcessPoolExecutor, as_completed

from utils.file_utils import load_wordlist, load_target
from utils.hash_utils import crack_chunk_wrapper
from utils.interface import get_command_line_args, display_summary

PASSWORD_LIST = "refs/dictionary_eng.txt"
COLOR = "\033[0;35m"
RESET = "\033[0m"

def process_future_result(future, status_flag):
    """Process the result of a completed future."""
    try:
        # Attempt to retrieve the result of the future
        result = future.result()
        print("Future result retrieved successfully.")  # Debug statement

        if result:  # Check if a match was found
            status_flag["found"] = True  # Set flag to stop other processes
            print(f"{COLOR}Password match found: {RESET}{result}")
            return True  # Indicate that a match was found

    except Exception as e:
        # Print the exception along with the traceback to locate the exact problem
        import traceback
        print(f"Error encountered in process_future_result: {e}")
        traceback.print_exc()
    
    # Indicate that no match was found if no exceptions were raised
    return False  # No match found

def main():
    start_time = time.time()

    args = get_command_line_args()
    hash_string = load_target(args)

    num_cores = os.cpu_count()
    cpu_workers = num_cores
    batch_size = 5000
    max_in_flight_futures = num_cores * 2  # Control the number of concurrent tasks

    # Manager for multiprocessing, creating an Event "found_flag" for password match status.
    manager = Manager()
    status_flag = manager.dict()
    status_flag["found"] = False
    status_flag["count"] = 0
    status_flag["summary"] = False
    status_flag["start"] = start_time
    status_flag["end"] = None


    # Initialize ProcessPoolExecutor to utilize 'num_workers' for hash processing.
    with ProcessPoolExecutor(max_workers=cpu_workers) as process_executor:
        futures = []  # List to store 'future' instances of each password-checking task.

        for chunk in load_wordlist(PASSWORD_LIST, batch_size):
            if status_flag["found"]:
                break

            # Submit each chunk to ProcessPoolExecutor directly
            future = process_executor.submit(crack_chunk_wrapper, hash_string, chunk, status_flag)
            futures.append(future)

            # If we have reached the limit of concurrent futures, wait for one to complete
            if len(futures) >= max_in_flight_futures:
                # Wait for one of the futures to complete before adding more
                for completed_future in as_completed(futures):
                    match_found = process_future_result(completed_future, status_flag)
                    if match_found and not status_flag["summary"]:
                        status_flag["message"] = "Match found and program terminated."
                        status_flag["end"] = time.time()
                        display_summary(cpu_workers, max_in_flight_futures, batch_size, status_flag)
                        return  # Exit immediately if a match is found

                    # Clean up completed futures to maintain the limit
                    futures = [f for f in futures if not f.done()]
                    break  # Exit after processing one completed future to keep submitting new chunks

        # Handle any remaining futures after loading all chunks
        for future in as_completed(futures):
            match_found = process_future_result(future, status_flag)
            if match_found and not status_flag["summary"]:
                status_flag["message"] = "Match found and program terminated."
                status_flag["end"] = time.time()
                display_summary(cpu_workers, max_in_flight_futures, batch_size, status_flag)
                return

    if not status_flag["found"]:  # No password match found.
        status_flag["message"] = "No match found in word list. Program terminated."
        status_flag["end"] = time.time()
        display_summary(cpu_workers, max_in_flight_futures, batch_size, status_flag)

if __name__ == "__main__":
    main()
