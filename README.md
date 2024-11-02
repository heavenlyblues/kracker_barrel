# Password Cracker with Parallel Processing

This Python project implements a multi-process password cracker using bcrypt and a wordlist. It efficiently distributes password checks across multiple processes to search for a bcrypt match within a provided hash. The program terminates immediately upon finding a match, reducing unnecessary computations.

## Features
- Uses Python's `ProcessPoolExecutor` to parallelize bcrypt password checks.
- Reads and divides a wordlist into chunks, processing each chunk independently.
- Efficiently terminates once a matching password is found.

## Requirements
- Python 3.x
- `bcrypt` library (`pip install bcrypt`)

## Usage
1. Place the target bcrypt hash in a file named `password_to_crack` under `refs/`.
2. Provide a wordlist (e.g., `rockyou.txt`) in `refs/` with passwords to attempt.

To run the program:
bash
python3 cracker_barrel.py