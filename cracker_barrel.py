import os
import time
from multiprocessing import Manager
from concurrent.futures import ProcessPoolExecutor, as_completed

from argon2 import PasswordHasher
import bcrypt
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from utils.file_utils import get_command_line_args, load_target

def create_hash_function(hash_func, salt, test_mode):
    """Create a hashing object based on the specified hash algorithm and test mode."""
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

def crack_chunk(hash_func, salt, target_hash, chunk, status_flags):
    """Process a chunk of passwords to find a match for the target hash."""
    if status_flags["found_flag"]:
        return False, 0  # Exit if the password has been found elsewhere
    
    # Reusable hash object for Argon and bcrypt only (single-use for others)
    reusable_hash_object = None
    if hash_func == "argon":
        reusable_hash_object = create_hash_function("argon", salt, status_flags.get("test_mode", False))
    
    passwords_attempted = 0

    for known_password in chunk:
        if status_flags["found_flag"]:
            return False, passwords_attempted

        passwords_attempted += 1
    
        if passwords_attempted % 1000 == 0:
            print(f"Processing: {known_password.decode()} (Type: {type(known_password)})")
        
        try:
            # Check for Argon2
            if hash_func == "argon" and reusable_hash_object.verify(target_hash, known_password):
                status_flags["found_flag"] = True
                return known_password, passwords_attempted

            # Check for bcrypt
            elif hash_func == "bcrypt" and bcrypt.checkpw(known_password, target_hash):
                status_flags["found_flag"] = True
                return known_password, passwords_attempted

            # Check for single-use Scrypt
            elif hash_func == "scrypt":
                scrypt_object = create_hash_function("scrypt", salt, status_flags.get("test_mode", False))
                if scrypt_object.derive(known_password) == target_hash:
                    status_flags["found_flag"] = True
                    return known_password.decode(), passwords_attempted

            # Check for single-use PBKDF2
            elif hash_func == "pbkdf2":
                pbkdf2_object = create_hash_function("pbkdf2", salt, status_flags.get("test_mode", False))
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
def load_wordlist(wordlist_path, batch_size=1000):
    with open(wordlist_path, "r", encoding="latin-1") as file:
        batch = []
        for line in file:
            batch.append(line.strip().encode())
            if len(batch) >= batch_size:
                yield batch  # Yield a full batch of passwords
                batch = []   # Reset batch for the next set of lines
        if batch:  # Yield any remaining lines as the final batch
            yield batch

    # Manager for multiprocessing, creating a shared dictionary "found_flag" for password match status.
    # All processes running 'crack_chunk_wrapper' can consistently check and update found_flag.            
def initialize_shared_resources(test_mode):
    # Initialize a Manager and shared dictionary
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
    
    total_attempted = 0

    status_flags = initialize_shared_resources(test_mode)
    password_batches = load_wordlist("refs/rockyou_med.txt", batch_size)

    # Initialize ProcessPoolExecutor to utilize 'num_workers' for hash processing.
    with ProcessPoolExecutor(max_workers=cpu_workers) as process_executor:
        futures = []  # List to store 'future' instances of each password-checking task.
        
        for chunk in password_batches:
            if status_flags["found_flag"]:
                break

            # Submit each chunk to ProcessPoolExecutor directly
            future = process_executor.submit(crack_chunk_wrapper, hash_func, salt, target_hash, chunk, status_flags)
            futures.append(future)

        # Iterate over 'future' executions of attempt_crack as they are complete.
        for future in as_completed(futures):      
            try:
                result, passwords_attempted = future.result()  # Retrieve the result from each future
                total_attempted += passwords_attempted

                if result:  # Check if result is a matching password
                    status_flags["found_flag"] = True  # Set the flag so other tasks stop
                    end_time = time.time()
                    print(f"Password match found: {result}")
                    print(f"Total passwords attempted: {total_attempted}")
                    print(f"Total time: {end_time - start_time:1f}")
                    print("Match found and program terminated.")    
                    break  # Exit loop if a match is found

            except Exception as e:
                print(f"Error encountered: {e}")
    
    if not status_flags["found_flag"]: # No password match found.
        end_time = time.time()
        print(f"Total passwords attempted: {total_attempted}")
        print(f"Total time: {end_time - start_time:1f}")
        print("No match found in word list. Program terminated.")

if __name__ == "__main__":
    main()