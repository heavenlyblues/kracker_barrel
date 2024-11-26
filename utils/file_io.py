from pathlib import Path
import sys


# Load input file with target hash
def load_target_hash(target_filepath):
    try:
        with target_filepath.open("r") as file:
            lines = file.readlines()
            if len(lines) == 0:
                print("Empty file. Nothing to read.")
                return None
            elif len(lines) == 1:
                hash_digest_with_metadata = lines[0].strip()  # Single hash
                return [hash_digest_with_metadata]  # Return as a list
            else:
                multihash_digest = [line.strip() for line in lines]  # Multiple hashes
                return multihash_digest
    except FileNotFoundError:
        print("Error: Target file not found.")
        sys.exit(1)
    
    return hash_digest_with_metadata


# Generator function to load the wordlist in batches
def yield_dictionary_batches(path_to_passwords, batch_size):
    try:
        total_passwords = 0  # Counter for debugging
        with path_to_passwords.open("r", encoding="latin-1", errors="replace") as file:
            batch = []
            for line_number, line in enumerate(file, start=1):
                password = line.strip()
                batch.append(password)
                total_passwords += 1

                # Yield a full batch when the batch size is met
                if len(batch) >= batch_size:
                    print(f"Yielding batch of size {len(batch)} at line {line_number}, Total passwords so far: {total_passwords}")
                    yield batch
                    batch = []  # Reset batch for the next set of lines

            # Yield any remaining passwords as the final batch
            if batch:
                print(f"Yielding final batch of size {len(batch)}, Total passwords: {total_passwords}")
                yield batch

        print(f"Total passwords processed: {total_passwords}")

    except FileNotFoundError:
        print(f"Error: File {path_to_passwords} not found.")
    except Exception as e:
        print(f"Error while reading passwords: {e}")


def get_number_of_passwords(path_to_passwords):
    with path_to_passwords.open("r", encoding="latin-1", errors="replace") as file:
        return sum(1 for _ in file)