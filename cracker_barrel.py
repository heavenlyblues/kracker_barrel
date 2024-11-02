import bcrypt
import time
from concurrent.futures import ProcessPoolExecutor


def attempt_crack(target_hash, wordlist_chunk):
    for known_password in wordlist_chunk:
        known_password = known_password.strip()  # Clean up the newline
        if bcrypt.checkpw(known_password.encode(), target_hash):
            return known_password
    return None

def crack_with_chunk(args):
    target_hash, chunk = args
    return attempt_crack(target_hash, chunk)

def generate_chunks(wordlist, target_hash, chunk_size):
    """Generator to yield (target_hash, chunk) tuples."""
    for i in range(0, len(wordlist), chunk_size):
        yield target_hash, wordlist[i:i + chunk_size]

def main():
    start = time.time()

    with open("refs/password_to_crack", "rb") as file:
        target_hash = file.read()

    with open("refs/rockyou_sm.txt", "r", encoding="latin-1") as file:
        wordlist = file.readlines()

    num_workers = 8
    length = len(wordlist)
    chunk_size = length // num_workers

    wordlist_chunks = [wordlist[i:i + chunk_size] for i in range(0, length, chunk_size)]
    if length % num_workers != 0:  # Add the remainder to the last chunk
        wordlist_chunks[-1].extend(wordlist[length - (length % num_workers):])

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        results = executor.map(crack_with_chunk, generate_chunks(wordlist, target_hash, chunk_size))
    
    for result in results:
        if result:
            print(f"Password match found: {result}")
            break
    else:
        print("No match found in word list.")
    
    end = time.time()

    print(f"Total time: {end - start}")


if __name__ == "__main__":
    main()