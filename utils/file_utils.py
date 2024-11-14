import sys
from pathlib import Path

# Load input file with target hash
def load_target_hash(target_filepath):
    try:
        with target_filepath.open("r") as file:
            hash_digest_with_metadata = file.readline().strip()

    except FileNotFoundError:
        print("Error: Target file not found.")
        sys.exit(1)
    
    return hash_digest_with_metadata


# Generator function to load the wordlist in batches
def yield_password_batches(path_to_passwords, batch_size):
    try:
        with path_to_passwords.open("r", encoding="latin-1") as file:
            batch = []
            for line in file:
                batch.append(line.strip().encode())
                if len(batch) >= batch_size:
                    yield batch  # Yield a full batch of passwords
                    batch = []  # Reset batch for the next set of lines
            if batch:  # Yield any remaining lines as the final batch
                yield batch

    except FileNotFoundError:
        print(f"{path_to_passwords} - File not found.")


def get_number_of_passwords(path_to_passwords):
    with path_to_passwords.open("r", encoding="latin-1") as file:
        return sum(1 for _ in file)