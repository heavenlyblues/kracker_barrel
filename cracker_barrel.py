import os
import time
from multiprocessing import Manager
from concurrent.futures import ProcessPoolExecutor, as_completed

from argon2 import PasswordHasher
import bcrypt
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from utils.file_utils import PASSWORD_LIST, get_command_line_args, load_target

def create_hash_function(hash_func, salt, test_mode_flagged):
    """Create a hashing object based on the specified hash algorithm and test mode."""
    if hash_func == "argon":
        return PasswordHasher(
            time_cost=1 if test_mode_flagged else 3, 
            memory_cost=2**10 if test_mode_flagged else 12288, 
            parallelism=1
        )
    elif hash_func == "scrypt":
        return Scrypt(
            salt=salt, length=32, 
            n=2**8 if test_mode_flagged else 2**14, 
            r=18 if test_mode_flagged else 8, 
            p=1 if test_mode_flagged else 5
        )
    elif hash_func == "pbkdf2":
        return PBKDF2HMAC(
            algorithm=hashes.SHA512(), 
            length=32, salt=salt, 
            iterations=1000 if test_mode_flagged else 210000
        )
    return None  # bcrypt is handled directly without helper function

def crack_chunk(hash_func, salt, target_hash, chunk, status_flags):
    """Process a chunk of passwords to find a match for the target hash."""
    if status_flags["found_flag"]:
        return False, 0  # Exit if the password has been found elsewhere
    
    test_mode_flagged = status_flags["test_mode"]
    reusable_hash_object = None
    passwords_attempted = 0

    if hash_func == "argon":
        reusable_hash_object = create_hash_function("argon", salt, test_mode_flagged)
    

    for known_password in chunk:
        if status_flags["found_flag"]:
            return False, passwords_attempted

        passwords_attempted += 1
    
        if passwords_attempted % 5000 == 0:
            print(f"Processing: {known_password.decode()} (Type: {type(known_password)})")
        
        try:
            # Check for Argon2
            if hash_func == "argon" and reusable_hash_object.verify(target_hash, known_password):
                status_flags["found_flag"] = True  # Use Event's set() method to signal found
                return known_password, passwords_attempted

            # Check for bcrypt
            elif hash_func == "bcrypt" and bcrypt.checkpw(known_password, target_hash):
                status_flags["found_flag"] = True
                return known_password, passwords_attempted

            # Check for single-use Scrypt
            elif hash_func == "scrypt":
                scrypt_object = create_hash_function("scrypt", salt, test_mode_flagged)
                if scrypt_object.derive(known_password) == target_hash:
                    status_flags["found_flag"] = True
                    return known_password.decode(), passwords_attempted

            # Check for single-use PBKDF2
            elif hash_func == "pbkdf2":
                pbkdf2_object = create_hash_function("pbkdf2", salt, test_mode_flagged)
                if pbkdf2_object.derive(known_password) == target_hash:
                    status_flags["found_flag"] = True
                    return known_password.decode(), passwords_attempted
        
        except (TypeError, ValueError, MemoryError, Exception):
            # Suppressed all error messages
            pass
    
    return False, passwords_attempted

# Wrapper function to pass attempt_crack function into 'executor.submit' method.
# Allows for structured argument passing into attempt_crack.
def crack_chunk_wrapper(hash_func, salt, target_hash, chunk, status_flags):
    return crack_chunk(hash_func, salt, target_hash, chunk, status_flags)

# Generator function to load the wordlist in batches
def load_wordlist(wordlist_path, batch_size):
    chunk_time_start = time.time()
    try:
        with open(wordlist_path, "r", encoding="latin-1") as file:
            batch = []
            for line in file:
                batch.append(line.strip().encode())
                if len(batch) >= batch_size:
                    yield batch  # Yield a full batch of passwords
                    chunk_time_end = time.time()
                    print(f"Chunk load time: {chunk_time_end - chunk_time_start:1f}")
                    batch = []   # Reset batch for the next set of lines
            if batch:  # Yield any remaining lines as the final batch
                yield batch
    except FileNotFoundError:
        print(f"{wordlist_path} - File not found.")

def process_future_result(future, status_flags, total_attempted, start_time):
    """Process the result of a completed future."""
    try:
        result, passwords_attempted = future.result()
        total_attempted += passwords_attempted

        if result:  # Check if a match was found
            status_flags["found_flag"] = True  # Set flag to stop other processes
            end_time = time.time()
            print(f"Password match found: {result}")
            print(f"Total passwords attempted: {total_attempted}")
            print(f"Total time: {end_time - start_time:.2f} seconds")
            print("Match found and program terminated.")
            return True, total_attempted  # Indicate that a match was found

    except Exception as e:
        print(f"Error encountered: {e}")

    return False, total_attempted  # Indicate that no match was found

    # Manager for multiprocessing, creating an Event "found_flag" for password match status.      
def initialize_shared_resources(test_mode):
    manager = Manager()
    status_flags = manager.dict()
    status_flags["found_flag"] = False
    status_flags["test_mode"] = test_mode
    return status_flags
    
def main():
    start_time = time.time()
    
    args = get_command_line_args()
    hash_func, salt, target_hash, test_mode = load_target(args)
    
    num_cores = os.cpu_count()
    cpu_workers = num_cores
    batch_size = 5000
    max_in_flight_futures = num_cores * 2  # Control the number of concurrent tasks

    
    total_attempted = 0

    status_flags = initialize_shared_resources(test_mode)
    

    # Initialize ProcessPoolExecutor to utilize 'num_workers' for hash processing.
    with ProcessPoolExecutor(max_workers=cpu_workers) as process_executor:
        futures = []  # List to store 'future' instances of each password-checking task.
        
        for chunk in load_wordlist(PASSWORD_LIST, batch_size):
            if status_flags["found_flag"]:
                break

            # Submit each chunk to ProcessPoolExecutor directly
            future = process_executor.submit(crack_chunk_wrapper, hash_func, salt, target_hash, chunk, status_flags)
            futures.append(future)
        
            # If we have reached the limit of concurrent futures, wait for one to complete
            if len(futures) >= max_in_flight_futures:
                # Wait for one of the futures to complete before adding more
                for completed_future in as_completed(futures):
                    match_found, total_attempted = process_future_result(
                        completed_future, status_flags, total_attempted, start_time
                    )
                    if match_found:
                        return  # Exit immediately if a match is found

                    # Clean up completed futures to maintain the limit
                    futures = [f for f in futures if not f.done()]
                    break  # Exit after processing one completed future to keep submitting new chunks

        # Handle any remaining futures after loading all chunks
        for future in as_completed(futures):
            match_found, total_attempted = process_future_result(
                future, status_flags, total_attempted, start_time
            )
            if match_found:
                return
    
    if not status_flags["found_flag"]: # No password match found.
        end_time = time.time()
        print(f"Total passwords attempted: {total_attempted}")
        print(f"Total time: {end_time - start_time:1f}")
        print("No match found in word list. Program terminated.")

if __name__ == "__main__":
    main()