import argparse
import bcrypt
import os
import base64
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def hash_with_argon(test_password):
    ph = PasswordHasher(time_cost=3, memory_cost=12288, parallelism=1)
    return ph.hash(test_password).encode()

def hash_with_bcrypt(test_password):
    salt = bcrypt.gensalt(rounds=10)
    return bcrypt.hashpw(test_password, salt)

def hash_with_scrypt(test_password):
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=5)
    hashed_password = kdf.derive(test_password)
    stored_salt = base64.urlsafe_b64encode(salt).decode()
    decoded_hash = base64.urlsafe_b64encode(hashed_password).decode()
    return stored_salt + "$" + decoded_hash

def hash_with_pbkdf2(test_password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, salt=salt, iterations=210000)
    hashed_password = kdf.derive(test_password)
    stored_salt = base64.urlsafe_b64encode(salt).decode()
    decoded_hash = base64.urlsafe_b64encode(hashed_password).decode()
    return stored_salt + "$" + decoded_hash

def unique_filename(filename):
    while os.path.exists(filename):
        filename = input("File already exists. Enter a new file name: ")
    return filename

def save_to_file(output_file, hashed):
    hashed_password_filename = unique_filename(output_file)
    if isinstance(hashed, str):  # Use isinstance for type checking
        with open(f"../refs/{hashed_password_filename}", "w") as file:
            file.write(hashed)
            print("String")
    elif isinstance(hashed, bytes):
        with open(f"../refs/{hashed_password_filename}", "wb") as file:
            print("Byte-string")
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

    commands = {
        "argon": lambda: hash_with_argon,
        "bcrypt": lambda: hash_with_bcrypt,
        "scrypt": lambda: hash_with_scrypt,
        "pbkdf2": lambda: hash_with_pbkdf2
    }

    test_password = input("Password for testing: ").encode()

    for key, command in commands.items():
        if getattr(args, key):
            hashed = command()(test_password)
            save_to_file(args.output_file, hashed)
            print(f"Test password: {test_password.decode()}")
            print(f"Hashed using: {key}")
            print(f"Saved to: {args.output_file}")
            break
    
if __name__ == "__main__":
    main()