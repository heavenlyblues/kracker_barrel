import sys

# Generator function to load the wordlist in batches
def load_wordlist(wordlist_path, batch_size):
    try:
        with open(wordlist_path, "r", encoding="latin-1") as file:
            batch = []
            for line in file:
                batch.append(line.strip().encode())
                if len(batch) >= batch_size:
                    yield batch  # Yield a full batch of passwords
                    batch = []  # Reset batch for the next set of lines
            if batch:  # Yield any remaining lines as the final batch
                yield batch

    except FileNotFoundError:
        print(f"{wordlist_path} - File not found.")

def get_wordlist_length(wordlist_path):
    count = 0
    with open(wordlist_path, "r", encoding="latin-1") as file:
        for line in file:
            count += 1
    return count

# Load input file with target hash
def load_target(args):
    try:
        with open(f"data/{args.input_file}","r") as file:
            hash_string = file.readline().strip()

    except FileNotFoundError:
        print("Error: Target file not found.")
        sys.exit(1)
    
    return hash_string