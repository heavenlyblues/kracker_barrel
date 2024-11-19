from collections import Counter
import csv


def merge_and_deduplicate(output_file, *input_files):
    seen = set()
    with open(output_file, "w", encoding="utf-8") as outfile:
        for file in input_files:
            with open(file, "r", encoding="utf-8", errors="ignore") as infile:
                for line in infile:
                    password = line.strip()
                    if password not in seen:
                        outfile.write(password + "\n")
                        seen.add(password)


def merge_to_csv(output_csv, *input_files):
    """
    Merge password lists into a CSV file with columns: password, count.
    """
    password_counter = Counter()

    # Count passwords across all input files
    for file in input_files:
        with open(file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                password = line.strip()
                if password:
                    password_counter[password] += 1

    # Write the aggregated data to a CSV file
    with open(output_csv, "w", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["password", "count"])  # CSV header
        for password, count in password_counter.most_common():
            writer.writerow([password, count])


def append_to_csv(existing_csv, new_csv, new_wordlists):
    """
    Append new passwords to an existing CSV, updating counts for duplicates.
    """
    # Step 1: Load existing CSV into a Counter
    password_counter = Counter()
    try:
        with open(existing_csv, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                password = row["password"]
                count = int(row["count"])
                password_counter[password] += count
    except FileNotFoundError:
        print(f"{existing_csv} not found. Creating a new file.")
    
    # Step 2: Process new wordlists and update counts
    for wordlist in new_wordlists:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as infile:
            for line in infile:
                password = line.strip()
                if password:
                    password_counter[password] += 1

    # Step 3: Write the updated counts back to a new CSV
    with open(new_csv, "w", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["password", "count"])  # Write header
        for password, count in password_counter.most_common():
            writer.writerow([password, count])

    print(f"Updated CSV saved to {new_csv}.")


# merge_to_csv("refs/merged_passwords.csv", 
#              "refs/rockyou.txt", 
#              "refs/dictionary_eng.txt", 
#              "refs/sec_lists_master/Passwords/2023-200_most_used_passwords.txt"
# )

# append_to_csv(
#     existing_csv="refs/merged_passwords.csv",
#     new_csv="refs/updated_passwords.csv",
#     new_wordlists=["refs/sec_lists_master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt", 
#                    "refs/sec_lists_master/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt",
#                    "refs/sec_lists_master/Passwords/Common-Credentials/worst-passwords-2017-top100-slashdata.txt",
#                    "refs/sec_lists_master/Passwords/Leaked-Databases/faithwriters.txt"]
# )