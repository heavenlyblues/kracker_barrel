import argparse
import bcrypt
import os
import base64
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC



def hash_with_argon(tc, mc, p, test_password):
    ph = PasswordHasher(time_cost=tc, memory_cost=mc, parallelism=p)
    return ph.hash(test_password)

def hash_with_bcrypt(rounds, test_password):
    salt = bcrypt.gensalt(rounds=rounds)
    return bcrypt.hashpw(test_password, salt)

def hash_with_scrypt(salt, n, r, p, test_password):
    # Set up the Scrypt KDF
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    hashed = kdf.derive(test_password)

    # Encode salt and hash with base64 and decode to string
    salt_b64 = base64.urlsafe_b64encode(salt).decode("utf-8")
    hashed_b64 = base64.urlsafe_b64encode(hashed).decode("utf-8")

    # Return formatted string including scrypt settings
    return f"$scrypt$ln={n},r={r},p={p}${salt_b64}${hashed_b64}"

def hash_with_pbkdf2(iterations, salt, test_password):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, salt=salt, iterations=iterations)
    hashed = kdf.derive(test_password)
    # Encode salt and hash with base64 and decode to string
    salt_b64 = base64.urlsafe_b64encode(salt).decode("utf-8")
    hashed_b64 = base64.urlsafe_b64encode(hashed).decode("utf-8")
    return f"$pbkdf2_sha512$iterations={iterations}${salt_b64}${hashed_b64}"

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
        time_cost, memory_cost, parallelism = 1, 2**10, 1 # Argon
        rounds = 5              # Bcrypt
        salt = os.urandom(16)   # PBKDF2 & Scrypt
        n, r, p = 2**8, 18, 1   # Scrypt
        iterations = 1000       # PBDKF2
    else:
        time_cost, memory_cost, parallelism = 3, 12288, 1 # Argon
        rounds = 10             # Bcrypt
        salt = os.urandom(16)   # PBKDF2 & Scrypt
        n, r, p = 2**14, 8, 5   # Scrypt
        iterations = 210000     # PBDKF2

    commands = {
        "argon": lambda pwd: hash_with_argon(time_cost, memory_cost, parallelism, pwd),
        "bcrypt": lambda pwd: hash_with_bcrypt(rounds, pwd),
        "scrypt": lambda pwd: hash_with_scrypt(salt, n, r, p, pwd),
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