import argparse
import bcrypt
import os
import base64
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC



def hash_with_argon(ph, test_password):
    # ph = PasswordHasher(time_cost=3, memory_cost=12288, parallelism=1)
    return ph.hash(test_password)

def hash_with_bcrypt(rounds, test_password):
    salt = bcrypt.gensalt(rounds=rounds)
    return bcrypt.hashpw(test_password, salt)

def hash_with_scrypt(kdf, salt, test_password):
    # salt = os.urandom(16)
    # kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=5)
    hashed = kdf.derive(test_password)
    return base64.urlsafe_b64encode(salt) + base64.urlsafe_b64encode(hashed)

def hash_with_pbkdf2(iterations, salt, test_password):
    # salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, salt=salt, iterations=iterations)
    hashed = kdf.derive(test_password)
    return base64.urlsafe_b64encode(salt) + base64.urlsafe_b64encode(hashed)

def unique_filename(filename):
    while os.path.exists(filename):
        filename = input("File already exists. Enter a new file name: ")
    return filename

def save_to_file(output_file, hashed):
    hashed_password_filename = unique_filename(output_file)
    print(hashed)
    if isinstance(hashed, str):  # Use isinstance for type checking
        with open(f"data/{hashed_password_filename}", "w") as file:
            file.write(hashed)
            print("String")
    elif isinstance(hashed, bytes):
        with open(f"data/{hashed_password_filename}", "wb") as file:
            print("Bytes")
            file.write(hashed)
    return

def get_command_line_args():
    parser = argparse.ArgumentParser(
        description="Select a hash algorithm to hash a password for testing 'cracker_barrel.py'"
    )
    
    # Create a mutually exclusive group for the hash algorithm options
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-a", "--argon", 
        help="Generate Argon2id hash with parameters: m=2**14, t=3, p=1", 
        action="store_true"
    )
    group.add_argument(
        "-b", "--bcrypt", 
        help="Generate Bcrypt hash with minimum work factor of 10", 
        action="store_true"
    )
    group.add_argument(
        "-s", "--scrypt", 
        help="Generate Scrypt hash with parameters: N=2**14, r=8, p=5", 
        action="store_true"
    )
    group.add_argument(
        "-p", "--pbkdf2", 
        help="Generate PDKDF2 hash with parameters: algorithm=SHA512, iterations=210000", 
        action="store_true"
    )

    parser.add_argument(
        "-t", "--test_mode",
        help="Reduces hashing difficulty for testing purposes.",
        action="store_true"
    )

    # Required positional argument
    parser.add_argument(
        "output_file", 
        type=str, 
        help="Specify output file name."
    )

    args = parser.parse_args()

    # Check that the output_file argument is provided
    if not args.output_file:
        parser.error("the following argument is required: output_file")

    return args

def main():
    args = get_command_line_args()

    if args.test_mode:
        ph = PasswordHasher(time_cost=1, memory_cost=2**10, parallelism=1)
        rounds = 5
        salt = os.urandom(16)
        kdf = Scrypt(salt=salt, length=32, n=2**8, r=18, p=1)
        iterations = 1000
    else:
        ph = PasswordHasher(time_cost=3, memory_cost=12288, parallelism=1)
        rounds = 10
        salt = os.urandom(16)
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=5)
        iterations=210000

    commands = {
        "argon": lambda pwd: hash_with_argon(ph, pwd),
        "bcrypt": lambda pwd: hash_with_bcrypt(rounds, pwd),
        "scrypt": lambda pwd: hash_with_scrypt(kdf, salt, pwd),
        "pbkdf2": lambda pwd: hash_with_pbkdf2(iterations, salt, pwd)
    }

    test_password = input("Password for testing: ").encode()

    for key, command in commands.items():
        if getattr(args, key):
            hashed = command(test_password)
            save_to_file(args.output_file, hashed)
            print(f"Test password: {test_password.decode()}")
            print(f"Hashed using: {key}")
            print(f"Saved to: {args.output_file}")
            break
    
if __name__ == "__main__":
    main()