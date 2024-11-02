import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager
import bcrypt

# Checks found flag and processes a chunk of the list of known passwords.
# Reads one password at a time and checks for bcrypt match with the target hash.
# If a match is found, sets the 'found_flag' to True in shared_dict and returns the matching password.
# Returns False if no match is found within this chunk.
def attempt_crack(target_hash, wordlist_chunk, shared_dict):
    if not shared_dict["found_flag"]:
        print(f"Processing chunk with {len(wordlist_chunk)} passwords")
    for known_password in wordlist_chunk:
        if shared_dict["found_flag"]:
            return False
        print(f"Attempting password: {known_password} (Type: {type(known_password)})")
        if bcrypt.checkpw(known_password, target_hash):
            shared_dict["found_flag"] = True
            return known_password
    return False

# Wrapper function to pass attempt_crack function into 'executor.submit' method.
# Allows for structured argument passing into attempt_crack.
def crack_chunk_wrapper(target_hash, chunk, shared_dict):
    return attempt_crack(target_hash, chunk, shared_dict)

# Generator to yield chunks of the password list.
# Yields chunks of size 'chunk_size' for distribution across multiple processes.
def generate_chunks(wordlist, chunk_size):
    for i in range(0, len(wordlist), chunk_size):
        chunks = wordlist[i:i + chunk_size]
        print(f"Generated chunk with {len(chunks)} passwords")        
        yield chunks

def main():
    start = time.time()
    
    with open("refs/password_to_crack", "rb") as file:
        target_hash = file.read()

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
                    future = executor.submit(crack_chunk_wrapper, target_hash, chunk, shared_dict)
                    futures.append(future)

            # Iterate over 'future' executions of attempt_crack as they are complete.
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result: # Password match found.
                        print(f"Password match found: {result}")
                        end = time.time()
                        print(f"Total time: {end - start} seconds")
                        
                        # Immediately shut down executor to stop all other ongoing processes.
                        executor.shutdown(wait=False)
                        break            

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