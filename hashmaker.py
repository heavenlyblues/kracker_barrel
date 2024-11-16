from pathlib import Path
import argparse
import bcrypt
import os
import base64
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Hash import MD4
import hashlib


class HashMaker():
    def __init__(self, password, output_file):
        self.password = password
        self.output_file = output_file


    def _unique_filename(self):
        # Ensure the filename is inside the "data" directory
        file_path = Path("data") / self.output_file
        while file_path.exists():
            self.output_file = input(f"File {self.output_file} already exists. Enter a new file name: ")
            file_path = Path("data") / self.output_file  # Update the path to the new filename
        return file_path


    def compute_argon(self, tc, mc, p):
        ph = PasswordHasher(time_cost=tc, memory_cost=mc, parallelism=p)
        return ph.hash(self.password.encode())


    def compute_bcrypt(self, rounds):
        salt = bcrypt.gensalt(rounds=rounds)
        return bcrypt.hashpw(self.password.encode(), salt)


    def compute_scrypt(self, salt, n, r, p):
        # Set up the Scrypt KDF
        kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
        hashed = kdf.derive(self.password.encode())

        # Encode salt and hash with base64 and decode to string
        salt_b64 = base64.urlsafe_b64encode(salt).decode("utf-8")
        hashed_b64 = base64.urlsafe_b64encode(hashed).decode("utf-8")

        # Return formatted string including scrypt settings
        return f"$scrypt$ln={n},r={r},p={p}${salt_b64}${hashed_b64}"


    def compute_pbkdf2(self, iterations, salt):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, salt=salt, iterations=iterations)
        hashed = kdf.derive(self.password.encode())
        # Encode salt and hash with base64 and decode to string
        salt_b64 = base64.urlsafe_b64encode(salt).decode("utf-8")
        hashed_b64 = base64.urlsafe_b64encode(hashed).decode("utf-8")
        return f"$pbkdf2_sha512$iterations={iterations}${salt_b64}${hashed_b64}"


    # Function to hash a self.password using MD5
    def compute_md5(self):
        md5_hash = hashlib.md5(self.password.encode('utf-8')).hexdigest()
        return f"$md5${md5_hash}"


    # Function to compute the NTLM hash of a password
    def compute_ntlm(self):
        try:
            # Create the MD4 hash object
            md4_hash = MD4.new()
            md4_hash.update(self.password.encode('utf-16le'))  # Use UTF-16LE encoding

            # Compute the hash and get the raw bytes
            computed_hash = md4_hash.digest()

            # Convert the raw bytes to a hexadecimal string
            hex_hash = computed_hash.hex()

            # Return in the format: $ntlm$<32-character hash>
            return f"$ntlm${hex_hash}"
        except Exception as e:
            print(f"Error during NTLM hash computation: {e}")
            return ""


    # Function to hash a password using SHA-256
    def compute_sha256(self):
        sha256_hash = hashlib.sha256(self.password.encode('utf-8')).hexdigest()
        return f"$sha256${sha256_hash}"


    # Function to hash a password using SHA-512
    def compute_sha512(self):
        sha512_hash = hashlib.sha512(self.password.encode('utf-8')).hexdigest()
        return f"$sha512${sha512_hash}"


    def _save_to_file(self, hashed):
        # Ensure the "data" directory exists
        data_dir = Path("data")
        data_dir.mkdir(parents=True, exist_ok=True)

        # Get a unique filename inside the "data" directory
        hashed_password_filename = self._unique_filename()
        
        print(hashed)

        # Write the data to the file inside the "data" directory
        if isinstance(hashed, str):  # If the data is a string
            with open(hashed_password_filename, "w") as file:
                file.write(hashed)
                print("String")
        elif isinstance(hashed, bytes):  # If the data is bytes
            with open(hashed_password_filename, "wb") as file:
                file.write(hashed)
                print("Bytes")


# Parsing command line arguments
def get_command_line_args():
    parser = argparse.ArgumentParser(description="Password Hashing Utility")
    
    # Create a mutually exclusive group for the hash algorithm options
    parser.add_argument(
        "-o", "--operation", 
        choices=["argon", "bcrypt", "scrypt", "pbkdf2", "md5", "ntlm", "sha256", "sha512"],
        help="Choose a hash algorithm to use", 
        required=True
    )

    parser.add_argument("-t", "--test_mode", help="Test mode", action="store_true")
    parser.add_argument("--output_file", help="Specify output file name", type=str, default=None)

    return parser.parse_args()


def main():
    args = get_command_line_args()
    
    password = input("Password for testing: ").strip()

    hash_maker = HashMaker(password, args.output_file)

    if args.test_mode:
        time_cost, memory_cost, parallelism = 1, 2**10, 1 # Argon
        rounds = 5              # Bcrypt
        salt = os.urandom(16)   # PBKDF2 & Scrypt
        n, r, p = 2**8, 8, 1   # Scrypt memory cost, block size, parallelism
        iterations = 1000       # PBDKF2
    else:
        time_cost, memory_cost, parallelism = 3, 2**14, 1 # Argon
        rounds = 10             # Bcrypt
        salt = os.urandom(16)   # PBKDF2 & Scrypt
        n, r, p = 2**14, 8, 5   # Scrypt memory cost, block size, parallelism
        iterations = 210000     # PBDKF2

    commands = {
        "argon": lambda: hash_maker.compute_argon(time_cost, memory_cost, parallelism),
        "bcrypt": lambda: hash_maker.compute_bcrypt(rounds),
        "scrypt": lambda: hash_maker.compute_scrypt(salt, n, r, p),
        "pbkdf2": lambda: hash_maker.compute_pbkdf2(iterations, salt),
        "md5": lambda: hash_maker.compute_md5(),
        "ntlm": lambda: hash_maker.compute_ntlm(),
        "sha256": lambda: hash_maker.compute_sha256(),
        "sha512": lambda: hash_maker.compute_sha512()
    }


    selected_operation = args.operation
    hashed = commands[selected_operation]()

    print(f"Test password: {password}")
    print(f"Hashed using: {selected_operation}")
    print(f"Hash: {hashed}")

    if args.output_file is not None:
        hash_maker._save_to_file(hashed)
        print(f"Saved to: {args.output_file}")

    
if __name__ == "__main__":
    main()