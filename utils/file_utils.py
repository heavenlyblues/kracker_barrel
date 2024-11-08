import argparse
import base64
import sys

PASSWORD_LIST = "refs/rockyou_med.txt"
ARGON_FILE = "./data/strong_argon_pinkpop.enc"
BCRYPT_FILE = "./data/weak_bcrypt.enc"
SCRYPT_FILE = "./data/strong_scrypt.enc"
PBKDF2_FILE = "./data/strong_pbkdf2.enc"

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

    args = parser.parse_args()
    return args

def load_target(args):
    if args.argon:
        try:
            with open(ARGON_FILE, "r") as file:
                hash_string = file.readline().strip()
        except FileNotFoundError:
            print("Error: Argon target file not found.")
            sys.exit(1)

    elif args.bcrypt:
        try:
            with open(BCRYPT_FILE, "rb") as file:
                hash_string = file.read().decode()
        except FileNotFoundError:
            print("Error: Bcrypt target file not found.")
            sys.exit(1)

    elif args.scrypt:
        try:
            with open(SCRYPT_FILE, "r") as file:
                hash_string = file.readline().strip()
        except FileNotFoundError:
            print("Error: Scrypt target file not found.")
            sys.exit(1)

    elif args.pbkdf2:
        try:
            with open(PBKDF2_FILE, "r") as file:
                hash_string = file.readline().strip()
        except FileNotFoundError:
            print("Error: PBDFK2 target file not found.")
            sys.exit(1)

    return hash_string