from utils.file_utils import *

import bcrypt
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager
from itertools import islice

import time


# Checks found flag and processes a chunk of the list of known passwords.
# Reads one password at a time and checks for hash match with the target hash.
# Uses specific hash function to check hash depending on user input
# If a match is found, sets the 'found_flag' to True in shared_dict and returns the matching password.
# Returns False if no match is found within this chunk.
def crack_chunk(hash_func, salt, target_hash, wordlist_chunk, shared_dict):
    if not shared_dict["found_flag"]:
        print(f"Processing chunk with {len(wordlist_chunk)} passwords")
    
    for known_password in wordlist_chunk:
        if shared_dict["found_flag"]:
            return False
        
        print(f"Attempting password: {known_password} (Type: {type(known_password)})")
        if hash_func == "argon":
            # ph = PasswordHasher(time_cost=3, memory_cost=12288, parallelism=1) ## HEAVY MODE ##
            ph = PasswordHasher(time_cost=1, memory_cost=2**10, parallelism=1)  ## TESTING MODE - WEAK HASH ##
            try:
                if ph.verify(target_hash, known_password):
                    shared_dict["found_flag"] = True
                    return known_password
            except Exception: # as e:
                pass
                # print(f"Unexpected Argon2 error: {e}")

        elif hash_func == "bcrypt" and bcrypt.checkpw(known_password, target_hash):
            shared_dict["found_flag"] = True
            return known_password
        
        elif hash_func == "scrypt":
            # kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=5) ## HEAVY MODE ##
            kdf = Scrypt(salt=salt, length=32, n=2**8, r=18, p=1) ## TESTING MODE - WEAK HASH ##

            try:
                if kdf.derive(known_password) == target_hash:
                    shared_dict["found_flag"] = True
                    return known_password.decode()
            except Exception: # as e:
                pass
                # print(f"Unexpected Scrypt error: {e}")
        
        elif hash_func == "pbkdf2":
            # kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, salt=salt, iterations=210000) ## HEAVY MODE ##
            kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, salt=salt, iterations=1000) ## TESTING MODE - WEAK HASH ##
            try:
                if kdf.derive(known_password) == target_hash:
                    shared_dict["found_flag"] = True
                    return known_password.decode()
            except Exception: # as e:
                pass
                # print(f"Unexpected PBKDF2 error: {e}")
                
    return False

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
    target_hash, salt, hash_func = load_target(args)
    
    num_workers = 8
    chunk_size = 800

    # Manager for multiprocessing, creating a shared dictionary "found_flag" for password match status.
    # All processes running 'crack_chunk_wrapper' can consistently check and update found_flag.
    with Manager() as manager:
        shared_dict = manager.dict()
        shared_dict["found_flag"] = False

        wordlist_gen = load_wordlist("refs/rockyou.txt")

        # Initialize ProcessPoolExecutor to utilize 'num_workers' for distributed processing.
        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures = []  # List to store 'future' instances of each password-checking task.
            
            for chunk in generate_chunks(wordlist_gen, chunk_size):
                if shared_dict["found_flag"]:
                    break # Stop if match found
                
                # For every chunk, create a future instance of 'attempt_crack'.
                future = executor.submit(crack_chunk_wrapper, hash_func, salt, target_hash, chunk, shared_dict)
                futures.append(future)

            # Iterate over 'future' executions of attempt_crack as they are complete.
            for future in as_completed(futures):      
                try:
                    result = future.result()  # Retrieve the result from each future
                    if result:  # Check if result is a matching password
                        print(f"Password match found: {result}")
                        shared_dict["found_flag"] = True  # Set the flag so other tasks stop
                        end = time.time()
                        print(f"Total time: {end - start} seconds")
                        break  # Exit loop if a match is found
                except Exception as e:
                    print(f"Error encountered: {e}")
        
        if not shared_dict["found_flag"]: # No password match found.
            end = time.time()
            print(f"Total time: {end - start}")
            print("No match found in word list. Program terminated.")
        else: 
            print("Match found and program terminated.")

if __name__ == "__main__":
    main()