import os
import time
import base64
from multiprocessing import Manager
from concurrent.futures import ProcessPoolExecutor, as_completed

from argon2 import PasswordHasher
import bcrypt
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from utils.file_utils import PASSWORD_LIST, get_command_line_args, load_target

def add_base64_padding(b64_string):
    """Add padding to a base64-encoded string if necessary."""
    return b64_string + '=' * (-len(b64_string) % 4)

def create_hash_function(hash_string):
    """Create a hashing object based on the specified hash algorithm from hash_string."""
    parts = hash_string.split('$')

    # Ensure the expected number of parts
    if len(parts) < 5:
        target_hash = hash_string
        return "bcrypt", target_hash, None

    elif "argon" in parts[1]:
        # Expected format: $argon2id$v=19$m=1024,t=1,p=1$salt$hash
        if len(parts) != 6 or parts[0] != "":
            raise ValueError("Invalid Argon2 hash format")
        
        try:
            # Parse the version
            version = int(parts[2].split('=')[1])

            # Parse memory, time, and parallelism values individually
            param_string = parts[3]  # m=1024,t=1,p=1
            memory_cost = int(param_string.split(',')[0].split('=')[1])  # m=1024
            time_cost = int(param_string.split(',')[1].split('=')[1])  # t=1
            parallelism = int(param_string.split(',')[2].split('=')[1])  # p=1

            # Decode the salt and target hash, ensuring padding
            target_hash = hash_string

        except (IndexError, ValueError) as e:
            raise ValueError(f"Error parsing Argon2 hash string: {e}")

        # Return the target_hash and PasswordHasher instance
        return "argon", target_hash, PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism
        )
    
    if "scrypt" in parts[1]:
        # Expected format: $scrypt$ln=16384,r=8,p=1$salt$hash
        if len(parts) != 5 or parts[0] != "":
            raise ValueError("Invalid scrypt hash format")
        
        # Parse parameters
        n = int(parts[2].split('=')[1].split(',')[0])
        r = int(parts[2].split(',')[1].split('=')[1])
        p = int(parts[2].split(',')[2].split('=')[1])
        salt_b64 = add_base64_padding(parts[3])
        hash_b64 = add_base64_padding(parts[4])
        
        # Decode salt and target hash
        salt = base64.urlsafe_b64decode(salt_b64)
        target_hash = base64.urlsafe_b64decode(hash_b64)
        
        # Return target_hash and scrypt KDF instance
        return "scrypt", target_hash, Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    
    elif "pbkdf2" in parts[1]:
        # Expected format: $pbkdf2_sha512$iterations=210000$salt$hash
        if len(parts) != 5 or parts[0] != "":
            raise ValueError("Invalid PBKDF2 hash format")

        # Parse parameters
        iterations = int(parts[2].split('=')[1])
        salt_b64 = add_base64_padding(parts[3])
        hash_b64 = add_base64_padding(parts[4])

        # Decode salt and target hash
        salt = base64.urlsafe_b64decode(salt_b64)
        target_hash = base64.urlsafe_b64decode(hash_b64)

        # Return target_hash and PBKDF2 KDF instance
        return "pbkdf2", target_hash, PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=iterations
        )
    
    else:
        raise ValueError("Unsupported hash function")
    
def crack_chunk(hash_string, chunk, status_flag):
    """Process a chunk of passwords to find a match for the target hash."""
    if status_flag['found']:
        return False, 0  # Exit if the password has been found elsewhere
    
    passwords_attempted = 0

    hash_func, target_hash, hash_object = create_hash_function(hash_string)

    for known_password in chunk:
        if status_flag['found']:
            return False, passwords_attempted

        passwords_attempted += 1
    
        if passwords_attempted % 5000 == 0:
            print(f"Processing: {known_password.decode()} (Type: {type(known_password)})")
            print(f"Verifying target hash: {target_hash} with password: {known_password.decode()}")

        try:
            # Check for Argon2
            if hash_func == "argon" and hash_object.verify(target_hash, known_password):
                status_flag['found'] = True  # Use Event's set() method to signal found
                return known_password, passwords_attempted

            # Check for bcrypt
            elif hash_func == "bcrypt" and bcrypt.checkpw(known_password, target_hash):
                status_flag['found'] = True
                return known_password, passwords_attempted

            # Check for Scrypt
            elif hash_func == "scrypt" and hash_object.derive(known_password) == target_hash:
                status_flag['found'] = True
                return known_password.decode(), passwords_attempted

            # Check for PBKDF2
            elif hash_func == "pbkdf2" and hash_object.derive(known_password) == target_hash:
                status_flag['found'] = True
                return known_password.decode(), passwords_attempted
        
        except (TypeError, ValueError, MemoryError, Exception):
            # Suppressed all error messages
            pass
    
    return False, passwords_attempted

# Wrapper function to pass attempt_crack function into 'executor.submit' method.
# Allows for structured argument passing into attempt_crack.
def crack_chunk_wrapper(hash_string, chunk, status_flag):
    return crack_chunk(hash_string, chunk, status_flag)

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

def process_future_result(future, status_flag, total_attempted, start_time):
    """Process the result of a completed future."""
    try:
        result, passwords_attempted = future.result()
        total_attempted += passwords_attempted

        if result:  # Check if a match was found
            status_flag['found'] = True  # Set flag to stop other processes
            end_time = time.time()
            print(f"Password match found: {result}")
            print(f"Total passwords attempted: {total_attempted}")
            print(f"Total time: {end_time - start_time:.2f} seconds")
            print("Match found and program terminated.")
            return True, total_attempted  # Indicate that a match was found

    except Exception as e:
        print(f"Error encountered: {e}")

    return False, total_attempted  # Indicate that no match was found
    
def main():
    start_time = time.time()
    
    args = get_command_line_args()
    hash_string = load_target(args)
    
    num_cores = os.cpu_count()
    cpu_workers = num_cores
    batch_size = 5000
    max_in_flight_futures = num_cores * 2  # Control the number of concurrent tasks

    total_attempted = 0
    
    # Manager for multiprocessing, creating an Event "found_flag" for password match status.      
    manager = Manager()
    status_flag = manager.dict()
    status_flag['found'] = False
    

    # Initialize ProcessPoolExecutor to utilize 'num_workers' for hash processing.
    with ProcessPoolExecutor(max_workers=cpu_workers) as process_executor:
        futures = []  # List to store 'future' instances of each password-checking task.
        
        for chunk in load_wordlist(PASSWORD_LIST, batch_size):
            if status_flag['found']:
                break

            # Submit each chunk to ProcessPoolExecutor directly
            future = process_executor.submit(crack_chunk_wrapper, hash_string, chunk, status_flag)
            futures.append(future)
        
            # If we have reached the limit of concurrent futures, wait for one to complete
            if len(futures) >= max_in_flight_futures:
                # Wait for one of the futures to complete before adding more
                for completed_future in as_completed(futures):
                    match_found, total_attempted = process_future_result(
                        completed_future, status_flag, total_attempted, start_time
                    )
                    if match_found:
                        return  # Exit immediately if a match is found

                    # Clean up completed futures to maintain the limit
                    futures = [f for f in futures if not f.done()]
                    break  # Exit after processing one completed future to keep submitting new chunks

        # Handle any remaining futures after loading all chunks
        for future in as_completed(futures):
            match_found, total_attempted = process_future_result(
                future, status_flag, total_attempted, start_time
            )
            if match_found:
                return
    
    if not status_flag['found']: # No password match found.
        end_time = time.time()
        print(f"Total passwords attempted: {total_attempted}")
        print(f"Total time: {end_time - start_time:1f}")
        print("No match found in word list. Program terminated.")

if __name__ == "__main__":
    main()