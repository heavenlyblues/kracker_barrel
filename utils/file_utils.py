import argparse
import base64
import sys

BCRYPT_FILE = "./refs/weak_bcrypt"
ARGON_FILE = "./refs/weak_argon"
SCRYPT_FILE = "./refs/weak_scrypt"
PBKDF2_FILE = "./refs/weak_pbkdf2"

def get_command_line_args():
    parser = argparse.ArgumentParser(
        description="Select a hashing algorithm to crack the password file"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-a", "--argon", 
        help="Argon2id hash with parameters: m=2**14, t=3, p=1", 
        action="store_true"
    )
    group.add_argument(
        "-b", "--bcrypt", 
        help="Bcrypt hash with minimum work factor of 10", 
        action="store_true"
    )
    group.add_argument(
        "-s", "--scrypt", 
        help="Scrypt hash with parameters: N=2**14, r=8, p=5", 
        action="store_true"
    )
    group.add_argument(
        "-p", "--pbkdf2", 
        help="PDKDF2 hash with parameters: algorithm=SHA512, iterations=210000", 
        action="store_true"
    )
    parser.add_argument(
        "-t", "--test_mode", 
        help="Configures weaker hash function setting for quicker testing", 
        action="store_true"
    )

    args = parser.parse_args()
    return args

def decode_base64_segments(concatenated_base64):
    # Salt is 16 bytes, so it will be 24 characters in Base64 (16 * 4 / 3 = 24)
    # Hashed password is 32 bytes, so it will be 44 characters in Base64 (32 * 4 / 3 = 44)
    salt_base64 = concatenated_base64[:24]         # First 24 characters for salt
    hashed_password_base64 = concatenated_base64[24:]  # Remaining characters for hashed password
    # Decode Base64 segments back to binary
    salt = base64.urlsafe_b64decode(salt_base64)      # Decode salt back to 16-byte binary
    target_hash = base64.urlsafe_b64decode(hashed_password_base64)  # Decode hash back to 32-byte binary
    return salt, target_hash

def load_target(args):
    salt = None

    if args.test_mode:
        test_mode = True

    if args.bcrypt:
        try:
            with open(BCRYPT_FILE, "rb") as file:
                target_hash = file.read()
            hash_func = "bcrypt"
        except FileNotFoundError:
            print("Error: Bcrypt target file not found.")
            sys.exit(1)

    elif args.argon:
        try:
            with open(ARGON_FILE, "r") as file:
                target_hash = file.read().strip()
            hash_func = "argon"
        except FileNotFoundError:
            print("Error: Argon target file not found.")
            sys.exit(1)

    elif args.scrypt:
        try:
            with open(SCRYPT_FILE, "r") as file:
                salt, target_hash = decode_base64_segments(file.read().strip())
            hash_func = "scrypt"
        except FileNotFoundError:
            print("Error: Scrypt target file not found.")
            sys.exit(1)

    elif args.pbkdf2:
        try:
            with open(PBKDF2_FILE, "r") as file:
                salt, target_hash = decode_base64_segments(file.read().strip())
            hash_func = "pbkdf2"
        except FileNotFoundError:
            print("Error: PBDFK2 target file not found.")
            sys.exit(1)

    return target_hash, salt, hash_func, test_mode