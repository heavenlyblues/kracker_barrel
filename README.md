
# Cracker Barrel: A Multiprocessing Password Cracker

Cracker Barrel is a powerful, parallelized password-cracking tool designed to test passwords against known hashed values using common cryptographic hashing algorithms. This tool is optimized for speed using Python’s `ProcessPoolExecutor` and supports concurrent batch processing to handle large wordlists efficiently.

## Table of Contents
- [Features](#features)
- [Getting Started](#getting-started)
- [Supported Hash Algorithms](#supported-hash-algorithms)
- [Customization](#customization)

## Features

- **Parallel Processing**: Optimized for multi-core systems with concurrent processing of password batches.
- **Configurable Batch Size**: Process large wordlists with adjustable batch sizes to suit system memory limits and processing power.
- **Multiple Hash Algorithms**: Supports Argon2, bcrypt, scrypt, and PBKDF2 with user-defined parameters.
- **Efficient Memory Usage**: Chunks of wordlists are loaded and processed as they are read, minimizing memory usage.
- **Error Handling**: Error handling could be more robust to ensure that exceptions are managed gracefully.

## Getting Started

### Options

- `-a`, `--argon`: Use the Argon2 hashing algorithm.
- `-b`, `--bcrypt`: Use the bcrypt hashing algorithm.
- `-s`, `--scrypt`: Use the scrypt hashing algorithm.
- `-p`, `--pbkdf2`: Use the PBKDF2 hashing algorithm.
- `-t`, `--test_mode`: Enable test mode to reduce hashing difficulty for faster testing.

### Supported Hash Algorithms

- **Argon2**: Memory-intensive hashing algorithm with configurable time and memory costs.
- **bcrypt**: A popular password-hashing algorithm with a work factor that adjusts difficulty.
- **scrypt**: Memory-hard key derivation function ideal for password hashing.
- **PBKDF2**: A well-established hash function that uses HMAC and is configurable with multiple iterations.

## Customization

### Adjusting Batch Size and Concurrency

To improve performance, you can adjust `batch_size` and `max_in_flight_futures` in the `main` function:

- **`batch_size`**: Controls the number of passwords processed per batch. A higher value can increase performance but may use more memory.
- **`max_in_flight_futures`**: Controls the number of concurrent tasks. Typically, twice the number of CPU cores is a good setting.

### Hashing Parameters

To configure hashing parameters, update values in `create_hash_function` to adjust the computational difficulty for each hash type. The `test_mode` flag enables reduced difficulty for testing purposes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
