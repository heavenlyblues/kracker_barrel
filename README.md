# Kracker Barrel: Multiprocessing Password Cracker

Cracker Barrel is an automated, high-performance password-cracking tool. Designed for extensive password testing, it operates using multiprocessing and auto-detection of hash parameters to handle varied cryptographic hashes, maximizing efficiency in password verification.

## Table of Contents
- [Features](#features)
- [Getting Started](#getting-started)
- [Supported Hash Algorithms](#supported-hash-algorithms)
- [Customization](#customization)
- [Test Tools: Hash Maker](#hash-maker-password-hash-generation-tool)

## Features

**Auto-Detection**: Automatically identifies hashing algorithm and parameters based on input hash.
**Parallel Processing**: Optimized for concurrent processing using Python’s ProcessPoolExecutor.
**Configurable Batch Size**: Handles large wordlists in batches suited to system memory and processing power.
**Multiple Hash Algorithms**: Supports Argon2, bcrypt, scrypt, and PBKDF2.
**Optimized Memory Usage**: Loads and processes wordlist chunks dynamically.
**Comprehensive Logging**: Provides process readout, including password attempts and chunk load times.

## Getting Started

Clone the repository and navigate to the project folder.

### Running Cracker Barrel

Cracker Barrel auto-detects the hash algorithm and parameters from the input hash, simplifying the command to start the cracking process. 

To start cracking, specify the file containing the hashed password:

`python cracker_barrel.py <hashed_password_file>`

### Options (retired)

In previous versions, users could select the hashing algorithm manually with the following flags:

- `-a`, `--argon`: Use Argon2 hashing algorithm.
- `-b`, `--bcrypt`: Use bcrypt.
- `-s`, `--scrypt`: Use scrypt.
- `-p`, `--pbkdf2`: Use PBKDF2HMAC.
- `-t`, `--test_mode`: Enable test mode.

<span style="color:darkred">*This manual selection has been replaced by automated detection, making these flags obsolete.</span>

### Supported Hash Algorithms

- **Argon2**: Memory-intensive hashing with time and memory cost configuration.
- **bcrypt**: Password hashing with adjustable work factor.
- **scrypt**: Memory-hard key derivation function.
- **PBKDF2**: Configurable with multiple iterations and HMAC.

## Customization

### Adjusting Batch Size and Concurrency

Optimize performance by adjusting the `batch_size` and `max_in_flight_futures` settings in the `main` function:
- **`batch_size`**: Controls passwords processed per batch. Higher values may boost performance but use more memory.
- **`max_in_flight_futures`**: Manages concurrent tasks; typically, twice the CPU core count yields good results on my system.

### Hashing Parameters

No need to configure hashing parameters anymore, values in `create_hash_function` automatically parse the hash string to adjust the computational difficulty for each hash type. *The `test_mode` flag has been removed in this branch.*

## Hash Maker: Password Hash Generation Tool

Cracker Barrel includes a companion tool, Hash Maker, which generates hashes with specified algorithms and parameters for testing Cracker Barrel’s cracking capabilities. Test mode in this script are faster to process but below industry security standards. When hashes are generated in the regular mode they meet the NIST standard.

### Using Hash Maker

Use hash_maker.py to create test hashes. The tool automatically adjusts difficulty parameters when using the --test_mode flag.

Example Usage:

- `python hash_maker.py -a output_file`

For Test Mode hashes, use:

- `python hash_maker.py -a output_file -t`

### Test Mode Parameters

- **Argon2**: Time cost, memory cost, and parallelism reduced.
- **bcrypt**: Reduced rounds.
- **scrypt**: Lowered N, r, and p parameters.
- **PBKDF2**: Fewer iterations.

### License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
