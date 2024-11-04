# Password Cracker Tool – work in progress

## Overview
This tool is designed to crack hashed passwords using various cryptographic algorithms. It supports multiple hashing algorithms such as Argon2, bcrypt, Scrypt, and PBKDF2. (Last two functions now currently working)

## Features
- Supports multiple hashing algorithms.
- Utilizes multiprocessing to enhance the cracking process.
- Handles large lists of potential passwords.
- Provides a clear display of processing status and results. (Can be refined)

## Requirements
- `bcrypt` library (`pip install bcrypt`)

## Usage
1. Place the target bcrypt hash in a file named `password_to_crack` under `refs/`.
2. Provide a wordlist (e.g., `rockyou.txt`) in `refs/` with passwords to attempt.

## How It Works

1.	Set up the hashing environment: Depending on the chosen algorithm, the tool prepares the environment, reads the salt and hash from a predefined file, and configures the KDF parameters.
2.	Password file processing: Passwords from a specified file (rockyou_sm.txt) are loaded and split into manageable chunks.
3.	Multiprocessing: Each chunk is processed in parallel across multiple processor cores.
4.	Verification: Each password is tested against the stored hash. If a match is found, the tool flags success and terminates further processing.

## Known Issues

- This branch (new-feature-branch) is currently in development, and some features may not be fully functional.

# Hash Generation Utility "test_hash.py"

The provided Python script hash_generator.py is designed to create hashed versions of passwords using four different cryptographic algorithms: Argon2, bcrypt, Scrypt, and PBKDF2. This utility is useful for generating hashes to test the password cracker tool.
