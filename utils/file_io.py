from itertools import islice
import logging
from pathlib import Path
import sys

# Load input file with target hash
def load_target_hash(target_filepath):
    try:
        with target_filepath.open("r") as file:
            lines = file.readlines()
            if len(lines) == 0:
                logging.warning("Empty file. Nothing to read.")
                return None
            elif len(lines) == 1:
                hash_digest_with_metadata = lines[0].strip()  # Single hash
                return [hash_digest_with_metadata]  # Return as a list
            else:
                multihash_digest = [line.strip() for line in lines]  # Multiple hashes
                return multihash_digest
    except FileNotFoundError:
        logging.error("Error: Target file not found.")
        sys.exit(1)
    
    return hash_digest_with_metadata

def validate_password_file(path_to_passwords):
    invalid_lines = []
    with path_to_passwords.open("r", encoding="latin-1", errors="replace") as file:
        for i, line in enumerate(file, start=1):
            try:
                line.encode("utf-8")  # Try encoding to ensure validity
            except UnicodeEncodeError:
                invalid_lines.append(i)
    return invalid_lines

# Generator function to load the wordlist in batches
def yield_dictionary_batches(path_to_passwords, batch_size):
    try:
        with path_to_passwords.open("r", encoding="latin-1", errors="replace") as file:
            while True:
                chunk = list(islice(file, batch_size))  # Read a larger chunk
                if not chunk:
                    break

                batch = []
                for line in chunk:
                    cleaned_line = line.strip()
                    
                    if "�" in cleaned_line:  # Detect replacement characters
                        logging.warning(f"Problematic line skipped: {cleaned_line}")
                        continue  # Skip problematic lines

                    # Add the cleaned line to the batch
                    batch.append(cleaned_line.encode("utf-8"))

                    if len(batch) >= batch_size:
                        yield batch
                        batch = []

                if batch:
                    yield batch
    except FileNotFoundError:
        logging.error(f"{path_to_passwords} - File not found.")


def get_number_of_passwords(path_to_passwords):
    with path_to_passwords.open("r", encoding="latin-1") as file:
        return sum(1 for _ in file)