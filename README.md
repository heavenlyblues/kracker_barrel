# Password Cracker Tool – work in progress

## Overview
This tool is designed to crack hashed passwords using various cryptographic algorithms. It supports multiple hashing algorithms such as Argon2, bcrypt, Scrypt, and PBKDF2.

## Features
- Supports multiple hashing algorithms.
- Utilizes multiprocessing to enhance the cracking process.
- Can handle large lists of potential passwords.
- Provides a clear display of processing status and results. (Should be refined with better readout options)

## Requirements
- argon2-cffi
- bcrypt
- cryptography
- passlib
- pycparser
- scrypt

## Usage*
1. Place the target hash in a directory `refs/`. 
2. Provide a wordlist (e.g., `rockyou.txt`) in `refs/` with passwords to attempt.
- Note 1: Currently must update file open in code to reference file
- Note 2: You must manually set the hashing attribute manually in the code to match target hash.

## How It Works

1.	Set up the hashing environment: Depending on the chosen algorithm, the tool reads the salt and hash from a predefined file, and configures the parameters based on user selection. **Needs to be more user friendly here**
2.	Password file processing: Passwords from a specified file (rockyou_sm.txt) are loaded and split into manageable chunks.
3.	Multiprocessing: Each chunk is processed in parallel across multiple processor cores.
4.	Verification: Each password is tested against the stored hash. If a match is found, the tool flags success and terminates further processing.

## Known Issues

- Note 1: Currently must update file name and path in code to reference target hash and chosen password list.
- Note 2: You must set the hashing attribute manually in the code to match target hash.

# Hash Generation Utility "test_hash.py"

The provided Python script hash_generator.py is designed to create hashed versions of passwords using four different cryptographic algorithms: Argon2, bcrypt, Scrypt, and PBKDF2. This utility is very useful for generating hashes to test the password cracker tool. Could possibly integrate into Cracker Barrel later. User selectable "testing mode" now available which creates weaker hashes for faster testing.
