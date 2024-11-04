import argparse
import base64
import re
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager
import bcrypt
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Checks found flag and processes a chunk of the list of known passwords.
# Reads one password at a time and checks for bcrypt match with the target hash.
# If a match is found, sets the 'found_flag' to True in shared_dict and returns the matching password.
# Returns False if no match is found within this chunk.
def attempt_crack(hash_func, salt, target_hash, wordlist_chunk, shared_dict):
    if not shared_dict["found_flag"]:
        print(f"Processing chunk with {len(wordlist_chunk)} passwords")
    
    for known_password in wordlist_chunk:
        if shared_dict["found_flag"]:
            return False
        
        print(f"Attempting password: {known_password} (Type: {type(known_password)})")
        if hash_func == "argon":
            ph = PasswordHasher(time_cost=3, memory_cost=12288, parallelism=1)
            try:
                if ph.verify(target_hash, known_password):
                    shared_dict["found_flag"] = True
                    return known_password
            except Exception as e:
                print(f"Argon2 verification failed: {e}")
            

        elif hash_func == "bcrypt" and bcrypt.checkpw(known_password, target_hash):
            shared_dict["found_flag"] = True
            return known_password
        
        elif hash_func == "scrypt":
            kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=5)
            if kdf.verify(known_password, target_hash):
                shared_dict["found_flag"] = True
                return known_password
            else:
                return False
        
        elif hash_func == "pbkdf2":
            kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, salt=salt, iterations=210000)
            if kdf.verify(known_password, target_hash):
                shared_dict["found_flag"] = True
                return known_password
            else:
                return False
                
    return False

# Wrapper function to pass attempt_crack function into 'executor.submit' method.
# Allows for structured argument passing into attempt_crack.
def crack_chunk_wrapper(hash_func, salt, target_hash, chunk, shared_dict):
    return attempt_crack(hash_func, salt, target_hash, chunk, shared_dict)

# Generator to yield chunks of the password list.
# Yields chunks of size 'chunk_size' for distribution across multiple processes.
def generate_chunks(wordlist, chunk_size):
    for i in range(0, len(wordlist), chunk_size):
        chunks = wordlist[i:i + chunk_size]
        print(f"Generated chunk with {len(chunks)} passwords")        
        yield chunks

def get_command_line_args():
    parser = argparse.ArgumentParser(
        description="Select a hashing algorithm to crack the password file"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-a", "--argon", 
        help="Argon2id hash with parameters: m=2**14, t=3, p=1", 
        action="store_true"
    )
    group.add_argument(
        "-b", "--bcrypt", 
        help="Bcrypt hash with minimum work factor of 10", 
        action="store_true"
    )
    group.add_argument(
        "-s", "--scrypt", 
        help="Scrypt hash with parameters: N=2**14, r=8, p=5", 
        action="store_true"
    )
    group.add_argument(
        "-p", "--pbkdf2", 
        help="PDKDF2 hash with parameters: algorithm=SHA512, iterations=210000", 
        action="store_true"
    )
    args = parser.parse_args()
    return args

def main():
    start = time.time()

    args = get_command_line_args()
    
    """
    # User input files later???

    hash_to_crack = input("Enter filename of hashed password: ")
    known_password_list = input("Enter list of pwned passwords to scan: ")
    """

    if args.bcrypt:
        with open("refs/goodstuff_bcrypt", "rb") as file:
            target_hash = file.read()
            salt = ""
            hash_func = "bcrypt"
    elif args.argon:
        with open("refs/goodstuff_argon", "r") as file:
            target_hash = file.read().strip()
            salt = ""
            hash_func = "argon"
    elif args.scrypt:
        with open("refs/goodstuff_scrypt", "rb") as file:
            for line in file:
                saltish = line[:24]
                hashish = line[25:]
                salt = base64.urlsafe_b64encode(saltish)
                target_hash = base64.urlsafe_b64encode(hashish)
                hash_func = "scrypt"
    elif args.pbkdf2:
        with open("refs/goodstuff_pbkdf2", "rb") as file:
            for line in file:
                saltish = line[:24]
                hashish = line[25:]
                salt = base64.urlsafe_b64encode(saltish)
                target_hash = base64.urlsafe_b64encode(hashish)
                hash_func = "pbkdf2"
    
    print(f"Salt is of type {type(salt)}: {salt}")
    print(f"Target hash is of tyoe {type(target_hash)}: {target_hash}")
    
    # Create a list of encoded passwords from file.
    wordlist = []
    with open("refs/rockyou_sm.txt", "r", encoding="latin-1") as file:
        for line in file:
            for word in line.strip().split():
                wordlist.append(word.encode())

    # Configure Process Pool Executor with worker count and chunk size per worker.
    num_workers = 8
    chunk_size = len(wordlist) // num_workers

    # Manager for multiprocessing, creating a shared dictionary "found_flag" for password match status.
    # All processes running 'crack_chunk_wrapper' can consistently check and update found_flag.
    with Manager() as manager:
        shared_dict = manager.dict()
        shared_dict["found_flag"] = False

        # Initialize ProcessPoolExecutor to utilize 'num_workers' for distributed processing.
        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures = [] # List to store 'future' instances of each password-checking task.
            for chunk in generate_chunks(wordlist, chunk_size):
                if chunk: # For every chuck, create a future instance of 'attempt_crack'.
                    future = executor.submit(crack_chunk_wrapper, hash_func, salt, target_hash, chunk, shared_dict)
                    futures.append(future)

            # Iterate over 'future' executions of attempt_crack as they are complete.
            for future in as_completed(futures):
                if shared_dict["found_flag"]:
                    for f in futures:
                        if not f.done():
                            f.cancel()  # Gracefully cancel remaining futures
                    break  # Exit loop once match is found                
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