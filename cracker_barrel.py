import bcrypt
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager


def attempt_crack(target_hash, wordlist_chunk, shared_dict):
    if shared_dict.get("found_flag", False):
        return False
    
    print(f"Processing chunk with {len(wordlist_chunk)} passwords")
    for known_password in wordlist_chunk:
        if shared_dict["found_flag"]:  # Check flag again within the loop
            return False
        print(f"Attempting password: {known_password} (Type: {type(known_password)})")
        if bcrypt.checkpw(known_password, target_hash):
            shared_dict["found_flag"] = True
            return known_password
    return False

def crack_with_chunk(target_hash, chunk, shared_dict):
    return attempt_crack(target_hash, chunk, shared_dict)

def generate_chunks(wordlist, chunk_size):
    """Generator to yield (target_hash, chunk) tuples."""
    for i in range(0, len(wordlist), chunk_size):
        chunks = wordlist[i:i + chunk_size]
        print(f"Generated chunk with {len(chunks)} passwords")        
        yield chunks

def main():
    start = time.time()
    
    with open("refs/password_to_crack", "rb") as file:
        target_hash = file.read()

    wordlist = []
    with open("refs/rockyou_sm.txt", "r", encoding="latin-1") as file:
        for line in file:
            for word in line.strip().split():
                wordlist.append(word.encode())

    num_workers = 8
    chunk_size = len(wordlist) // num_workers

    # Manager for shared dictionary
    with Manager() as manager:
        shared_dict = manager.dict()
        shared_dict["found_flag"] = False


        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures = []
            for chunk in generate_chunks(wordlist, chunk_size):
                if chunk:
                    future = executor.submit(crack_with_chunk, target_hash, chunk, shared_dict)
                    futures.append(future)

            # Iterate over futures as they complete
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        print(f"Password match found: {result}")
                        end = time.time()
                        print(f"Total time: {end - start} seconds")
                        
                        # Shutdown the executor immediately
                        executor.shutdown(wait=False)
                        break            

                except Exception as e:
                    print(f"Error encountered: {e}")
        
        if not shared_dict["found_flag"]:
            print("No match found in word list.")
        else: 
            print("Match found and program terminated.")

    end = time.time()
    print(f"Total time: {end - start}")


if __name__ == "__main__":
    main()