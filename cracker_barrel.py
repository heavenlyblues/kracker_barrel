from utils.file_utils import *

from argon2 import PasswordHasher
import bcrypt
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from multiprocessing import Manager
from itertools import islice
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

def crack_chunk(hash_func, salt, target_hash, wordlist_chunk, shared_dict):
    if shared_dict["found_flag"]:
        return False, 0  # Exit if the password has been found elsewhere
    
    print(f"Processing chunk with {len(wordlist_chunk)} passwords")

    # Create hash function object based on the hash_func and test_mode settings
    hash_object = create_hash_function(hash_func, salt, shared_dict.get("test_mode", False))
    
    attempted_count = 0

    for known_password in wordlist_chunk:
        if shared_dict["found_flag"]:
            return False, attempted_count

        attempted_count += 1 

        print(f"Attempting password: {known_password} (Type: {type(known_password)})")

        try:
            if hash_func == "argon":
                if hash_object.verify(target_hash, known_password):
                    shared_dict["found_flag"] = True
                    return known_password, attempted_count
            
            elif hash_func == "bcrypt" and bcrypt.checkpw(known_password, target_hash):
                shared_dict["found_flag"] = True
                return known_password, attempted_count
            
            elif hash_func == "scrypt":
                if hash_object.derive(known_password) == target_hash:
                    shared_dict["found_flag"] = True
                    return known_password.decode(), attempted_count
            
            elif hash_func == "pbkdf2":
                if hash_object.derive(known_password) == target_hash:
                    shared_dict["found_flag"] = True
                    return known_password.decode(), attempted_count
        
        except Exception as e:
            print(f"Error with {hash_func} hash verification: {e}")
    
    return False, attempted_count

# Wrapper function to pass attempt_crack function into 'executor.submit' method.
# Allows for structured argument passing into attempt_crack.
def crack_chunk_wrapper(hash_func, salt, target_hash, chunk, shared_dict):
    return crack_chunk(hash_func, salt, target_hash, chunk, shared_dict)

# Function to generate chunks from the generator
def generate_chunks(generator, chunk_size):
    while True:
        chunk = list(islice(generator, chunk_size))
        if not chunk:
            break
        print(f"Generated chunk with {len(chunk)} passwords")        
        yield chunk

# Generator function to load the wordlist
def load_wordlist(filepath):
    with open(filepath, "r", encoding="latin-1") as file:
        for line in file:
            yield line.strip().encode()


def main():
    start = time.time()
    
    # Refactored and moved all CLI and file handling to utils/file_utils.py
    args = get_command_line_args()
    target_hash, salt, hash_func, test_mode = load_target(args)
    
    num_cores = os.cpu_count()
    pool_workers = num_cores
    thread_workers = num_cores * 2
    chunk_size = 800
    total_attempted = 0

    # Manager for multiprocessing, creating a shared dictionary "found_flag" for password match status.
    # All processes running 'crack_chunk_wrapper' can consistently check and update found_flag.
    with Manager() as manager:
        shared_dict = manager.dict()
        shared_dict["found_flag"] = False
        shared_dict["test_mode"] = test_mode

        wordlist_gen = load_wordlist("refs/rockyou_med.txt")
        
        # Initialize ThreadPoolExecutor to process password file.
        with ThreadPoolExecutor(max_workers=thread_workers) as thread_executor:
            
            # Initialize ProcessPoolExecutor to utilize 'num_workers' for hash processing.
            with ProcessPoolExecutor(max_workers=pool_workers) as process_executor:
                futures = []  # List to store 'future' instances of each password-checking task.
                
                # ThreadPoolExecutor to generate chunks
                chunk_future = thread_executor.submit(generate_chunks, wordlist_gen, chunk_size)
                
                # For each chunk generated by ThreadPoolExecutor, submit it to ProcessPoolExecutor
                try:
                    for chunk in chunk_future.result():
                        if shared_dict["found_flag"]:
                            break
                
                        # For every chunk, create a future instance of 'attempt_crack'.
                        future = process_executor.submit(crack_chunk_wrapper, hash_func, salt, target_hash, chunk, shared_dict)
                        futures.append(future)

                except Exception as e:
                    print(f"Error while generating chunks: {e}")

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
            end = time.time()
            print(f"Total time: {end - start}")
            print(f"Total passwords attempted: {total_attempted}")
            print("No match found in word list. Program terminated.")
        else: 
            print("Match found and program terminated.")
        print({num_cores})

if __name__ == "__main__":
    main()