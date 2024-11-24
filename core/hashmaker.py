import argparse
import base64
import time
import os
from pathlib import Path
from argon2 import PasswordHasher
import bcrypt
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.Hash import MD4
import hashlib


DATA_DIR = Path(__file__).parent.parent / "data"


class HashMaker():
    def __init__(self, operation, passwords, output_file, test_mode, secure_mode):
        self.operation = operation
        self.passwords = passwords
        self.output_file = Path(output_file)
        self.file_path = None
        self.test_mode = test_mode
        self.secure_mode = secure_mode
        self.parameters = self.set_parameters()

    def set_parameters(self):
        if self.test_mode:
            return {
                "argon": {"time_cost": 1, "memory_cost": 1024, "parallelism": 1},
                "bcrypt": {"rounds": 5},
                "scrypt": {"salt_length": 12, "hash_length": 32, "n": 2**8, "r": 8, "p": 1},
                "pbkdf2": {"algorithm": hashes.SHA256(), "algo_text": "sha256", "iterations": 1000, "salt_length": 12, "hash_length": 32}
            }
        elif self.secure_mode:
            return {
                "argon": {"time_cost": 1, "memory_cost": 47104, "parallelism": 1},
                "bcrypt": {"rounds": 12},
                "scrypt": {"salt_length": 32, "hash_length": 64, "n": 2**17, "r": 8, "p": 1},
                "pbkdf2": {"algorithm": hashes.SHA512(), "algo_text": "sha512", "iterations": 600000, "salt_length": 32, "hash_length": 64}
            }
        else:
            return {
                "argon": {"time_cost": 3, "memory_cost": 12288, "parallelism": 1},
                "bcrypt": {"rounds": 10},
                "scrypt": {"salt_length": 16, "hash_length": 32, "n": 2**15, "r": 8, "p": 3},
                "pbkdf2": {"algorithm": hashes.SHA512(), "algo_text": "sha512", "iterations": 210000, "salt_length": 16, "hash_length": 32}
            }
        
    def compute_argon(self, time_cost, memory_cost, parallelism):
        """
        Compute Argon2 hashes using explicit keyword arguments.

        Parameters:
            time_cost (int): The time cost parameter.
            memory_cost (int): The memory cost parameter.
            parallelism (int): The degree of parallelism.
        """
        ph = PasswordHasher(
            time_cost=time_cost, 
            memory_cost=memory_cost, 
            parallelism=parallelism
        )
        hash_list = []
        for password in self.passwords:
            hash_list.append(ph.hash(password.encode()))
        return hash_list


    def compute_bcrypt(self, rounds):
        hash_list = []
        for password in self.passwords:
            salt = bcrypt.gensalt(rounds=rounds)
            hash_list.append(bcrypt.hashpw(password.encode(), salt))
        decoded_hashes = [hash.decode('utf-8') for hash in hash_list]
        return decoded_hashes


    def compute_scrypt(self, salt_length, hash_length, n, r, p):
        hash_list = []
        for password in self.passwords:
            # Set up the Scrypt KDF
            salt = os.urandom(salt_length)
            kdf = Scrypt(
                salt=salt, 
                length=hash_length, 
                n=n, 
                r=r, 
                p=p
            )
            hashed = kdf.derive(password.encode())

            # Convert salt to Base64 and hash to Hex
            salt_b64 = base64.urlsafe_b64encode(salt).decode("utf-8")
            hashed_hex = hashed.hex()

            # Create the formatted output string
            formatted_hash = f"$scrypt$n={n},r={r},p={p}${salt_b64}${hashed_hex}"
            hash_list.append(formatted_hash)

        return hash_list


    def compute_pbkdf2(self, algorithm, algo_text, iterations, salt_length, hash_length):
        hash_list = []
        
        for password in self.passwords:
            salt = os.urandom(salt_length)
            kdf = PBKDF2HMAC(
                algorithm=algorithm,
                length=hash_length, 
                salt=salt, 
                iterations=iterations
            )
            hashed = kdf.derive(password.encode())
            # Encode salt and hash with base64 and decode to string
            salt_b64 = base64.urlsafe_b64encode(salt).decode("utf-8")
            hashed_hex = hashed.hex()
            
            hash_list.append(f"$pbkdf2$a={algo_text},i={iterations}${salt_b64}${hashed_hex}")
        return hash_list


    # Function to hash a self.password using MD5
    def compute_md5(self):
        hash_list = []
        for password in self.passwords:
            md5_hash = hashlib.md5(password.encode('utf-8')).hexdigest()
            hash_list.append(f"$md5${md5_hash}")
        return hash_list


    # Function to compute the NTLM hash of a password
    def compute_ntlm(self):
        hash_list = []
        for password in self.passwords:
            # Create the MD4 hash object
            md4_hash = MD4.new()
            md4_hash.update(password.encode('utf-16le'))  # Use UTF-16LE encoding

            # Compute the hash and get the raw bytes
            computed_hash = md4_hash.digest()

            # Convert the raw bytes to a hexadecimal string
            hex_hash = computed_hash.hex()
            hash_list.append(f"$ntlm${hex_hash}")
        # Return in the format: $ntlm$<32-character hash>
        return hash_list


    # Function to hash a password using SHA-256
    def compute_sha256(self):
        hash_list = []
        for password in self.passwords:        
            sha256_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            hash_list.append(f"$sha256${sha256_hash}")
        return hash_list


    # Function to hash a password using SHA-512
    def compute_sha512(self):
        hash_list = []
        for password in self.passwords:        
            sha512_hash = hashlib.sha512(password.encode('utf-8')).hexdigest()
            hash_list.append(f"$sha512${sha512_hash}")
        return hash_list


    def _save_to_file(self, hashed, operation):
        try:
            try:
                # Ensure the "data" directory exists
                data_dir = DATA_DIR
                data_dir.mkdir(parents=True, exist_ok=True)
            except PermissionError as e:
                print(f"Error creating data directory: {e}")
                exit(1)

            # Get unique filenames for hashes and metadata
            hashed_password_filename = self._unique_filename()
            metadata_filename = hashed_password_filename.with_name(
                hashed_password_filename.stem + "_metadata" + hashed_password_filename.suffix
            )

            # Write the hashed data to the hash file
            with hashed_password_filename.open("w") as file:
                for item in hashed:
                    file.write(f"{item}\n")

            # Write metadata to the metadata file
            with metadata_filename.open("w") as meta_file:
                for password, hash in zip(self.passwords, hashed):
                    meta_file.write(f"Password: {password}\n")
                    meta_file.write(f"Hash: {hash}\n")
                    meta_file.write(f"Hashed using: {operation}\n")
                    meta_file.write(f"Parameters: {self.parameters[operation]}\n\n")
                    
            print(f"List saved to: {hashed_password_filename}")
            print(f"Metadata saved to: {metadata_filename}")
        except OSError as e:
            print(f"Error saving files: {e}")


    def _unique_filename(self):
        # Ensure the filename is inside the "data" directory
        self.file_path = DATA_DIR / self.output_file
        while self.file_path.exists():
            print(f"File {self.file_path} already exists.")
            self.output_file = f"{self.output_file.stem}_{int(time.time())}{self.file_path.suffix}"
            self.file_path = DATA_DIR / self.output_file
        return self.file_path
    

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
    parser.add_argument("-t", "--test_mode", help="Test mode", action="store_true", default=False)
    parser.add_argument("-s", "--secure_mode", help="Highly security mode", action="store_true", default=False)
    parser.add_argument("output_file", nargs="?", help="Specify output file name", type=str, default=None)

    return parser.parse_args()


def main():
    args = get_command_line_args()
    
    passwords = []

    while True:
        password = input("Password for hashing: ").strip()
        if password:
            passwords.append(password)
        
        while True:  # Nested loop for validating 'More?' input
            more_passwords = input("More? [Y/n] ").strip().lower()
            if more_passwords in ["y", "n"]:
                break
            print("Invalid input. Please enter 'Y' or 'N'.")
        
        if more_passwords == "n":
            break

    hash_maker = HashMaker(args.operation, passwords, args.output_file, args.test_mode, args.secure_mode)

    commands = {
        "argon": lambda: hash_maker.compute_argon(**hash_maker.parameters["argon"]),
        "bcrypt": lambda: hash_maker.compute_bcrypt(**hash_maker.parameters["bcrypt"]),
        "scrypt": lambda: hash_maker.compute_scrypt(**hash_maker.parameters["scrypt"]),
        "pbkdf2": lambda: hash_maker.compute_pbkdf2(**hash_maker.parameters["pbkdf2"]),
        "md5": lambda: hash_maker.compute_md5(),
        "ntlm": lambda: hash_maker.compute_ntlm(),
        "sha256": lambda: hash_maker.compute_sha256(),
        "sha512": lambda: hash_maker.compute_sha512()
    }

    hashed_passwords = commands[hash_maker.operation]()

    for password, hash in zip(hash_maker.passwords, hashed_passwords):
        print(f"Test password: {password}")
        print(f"Hashed using: {hash_maker.operation}")
        print(f"Hash: {hash}")

    if hash_maker.output_file is not None:
        hash_maker._save_to_file(hashed_passwords, hash_maker.operation)
        print(f"Saved to: {hash_maker.file_path}")

    
if __name__ == "__main__":
    main()