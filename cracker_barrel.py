from utils.file_utils import *
from utils.retry_utils import *

from argon2 import PasswordHasher
import bcrypt
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager
from itertools import islice
import logging
import time
import os

# Checks found flag and processes a chunk of the list of known passwords.
# Reads one password at a time and checks for hash match with the target hash.
# Uses specific hash function to check hash depending on user input
# If a match is found, sets the 'found_flag' to True in shared_dict and returns the matching password.
# Returns False if no match is found within this chunk.

# Helper function to create hash function objects based on hash_func and test_mode
def create_hash_function(hash_func, salt, test_mode):
    if hash_func == "argon":
        return PasswordHasher(
            time_cost=1 if test_mode else 3, 
            memory_cost=2**10 if test_mode else 12288, 
            parallelism=1
        )
    elif hash_func == "scrypt":
        return Scrypt(
            salt=salt, length=32, 
            n=2**8 if test_mode else 2**14, 
            r=18 if test_mode else 8, 
            p=1 if test_mode else 5
        )
    elif hash_func == "pbkdf2":
        return PBKDF2HMAC(
            algorithm=hashes.SHA512(), 
            length=32, salt=salt, 
            iterations=1000 if test_mode else 210000
        )
    return None  # bcrypt is handled directly without helper function

# Set up logging to file
logging.basicConfig(filename="hash_errors.log", level=logging.ERROR,
                    format="%(asctime)s %(levelname)s %(message)s")

def crack_chunk(hash_func, salt, target_hash, chunk, shared_dict):
    if shared_dict["found_flag"]:
        return False, 0  # Exit if the password has been found elsewhere
    
    print(f"Processing chunk with {len(chunk)} passwords")

    # Create hash function object based on the hash_func and test_mode settings
    hash_object = create_hash_function(hash_func, salt, shared_dict["test_mode"])
    attempted_count = 0

    for known_password in chunk:
        if shared_dict["found_flag"]:
            return False, attempted_count

        attempted_count += 1 
        print(f"Attempting password: {known_password} (Type: {type(known_password)})")
        
        try:
            if hash_func == "argon": 
                if hash_object.verify(target_hash, known_password):
                    shared_dict["found_flag"] = True
                    return known_password, attempted_count
            
            elif hash_func == "bcrypt": 
                if bcrypt.checkpw(known_password, target_hash):
                    shared_dict["found_flag"] = True
                    return known_password, attempted_count
            
            elif hash_func == "scrypt":
                if hash_object.derive(known_password) == target_hash:
                    print(f"Verifying scrypt target_hash: {target_hash}, password: {known_password}")
                    shared_dict["found_flag"] = True
                    return known_password.decode(), attempted_count
            
            elif hash_func == "pbkdf2":
                if hash_object.derive(known_password) == target_hash:
                    shared_dict["found_flag"] = True
                    return known_password.decode(), attempted_count
        
        except (TypeError, ValueError) as e:
            # Catch specific verification errors (e.g., mismatched data types)
            logging.error(f"{hash_func} verification failed for password "
                            f"{known_password.decode(errors='ignore')}: {e}")
            break  # Exit retry loop for unresolvable errors

        except MemoryError as e:
            # Log critical failure and raise custom error to terminate if needed
            logging.critical(f"MemoryError during {hash_func} "
                                f"verification for {known_password.decode(errors='ignore')}: {e}")
            raise CustomHashingError(f"Critical memory error with {hash_func}")

        except Exception as e:
            # Log unexpected errors with a retry mechanism
            logging.error(f"Unexpected {hash_func} error for password "
                            f"{known_password.decode(errors='ignore')}: {e}")
        continue
    
    return False, attempted_count

# Wrapper function to pass attempt_crack function into 'executor.submit' method.
# Allows for structured argument passing into attempt_crack.
def crack_chunk_wrapper(hash_func, salt, target_hash, chunk, shared_dict):
    return crack_chunk(hash_func, salt, target_hash, chunk, shared_dict)

# Generator function to load the wordlist in batches
def load_wordlist(filepath, batch_size=1000):
    with open(filepath, "r", encoding="latin-1") as file:
        batch = []
        for line in file:
            batch.append(line.strip().encode())
            if len(batch) >= batch_size:
                yield batch  # Yield a full batch of passwords
                batch = []   # Reset batch for the next set of lines
        if batch:  # Yield any remaining lines as the final batch
            yield batch

def run_cracker_barrel():
    # Refactored and moved all CLI and file handling to utils/file_utils.py
    args = get_command_line_args()
    hash_func, salt, target_hash, test_mode = load_target(args)
    
    num_cores = os.cpu_count()
    pool_workers = num_cores
    chunk_size = 1000
    total_attempted = 0

    # Manager for multiprocessing, creating a shared dictionary "found_flag" for password match status.
    # All processes running 'crack_chunk_wrapper' can consistently check and update found_flag.
    with Manager() as manager:
        shared_dict = manager.dict()
        shared_dict["found_flag"] = False
        shared_dict["test_mode"] = test_mode
        
        wordlist_gen = load_wordlist("refs/rockyou_med.txt", chunk_size)

        # Initialize ProcessPoolExecutor to utilize 'num_workers' for hash processing.
        with ProcessPoolExecutor(max_workers=pool_workers) as process_executor:
            futures = []  # List to store 'future' instances of each password-checking task.
            
            for chunk in wordlist_gen:
                if shared_dict["found_flag"]:
                    break

                # Submit each chunk to ProcessPoolExecutor directly
                future = process_executor.submit(crack_chunk_wrapper, hash_func, salt, target_hash, chunk, shared_dict)
                futures.append(future)

            # Iterate over 'future' executions of attempt_crack as they are complete.
            for future in as_completed(futures):      
                try:
                    result, attempted_count = future.result()  # Retrieve the result from each future
                    total_attempted += attempted_count

                    if result:  # Check if result is a matching password
                        print(f"Password match found: {result}")
                        shared_dict["found_flag"] = True  # Set the flag so other tasks stop
                        end = time.time()
                        print(f"Total time: {end - start} seconds")
                        print(f"Total passwords attempted: {total_attempted}")
                        break  # Exit loop if a match is found

                except Exception as e:
                    print(f"Error encountered: {e}")
        
        if not shared_dict["found_flag"]: # No password match found.
            print(f"Total passwords attempted: {total_attempted}")
            print("No match found in word list. Program terminated.")
        else: 
            print("Match found and program terminated.")

def main():
    start = time.time()
    
    # Run the main password-cracking task with retry logic
    run_with_retries(run_cracker_barrel, max_retries=3, delay=5)

    end = time.time()
    print(f"Total time: {end - start:2f}")

if __name__ == "__main__":
    main()