import base64
from argon2 import PasswordHasher
import bcrypt
from Crypto.Hash import MD4
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import hashlib


class HashHandler:
    def __init__(self, hash_digest_with_metadata):
        self.hash_digest_with_metadata = hash_digest_with_metadata
        self.target_hash_to_crack = []
        self.hash_processor = None

    def parse_hash_digest_with_metadata(self):
        raise NotImplementedError("Subclasses must implement this method.")

    def verify(self, potential_password_match):
        raise NotImplementedError("Subclasses must implement this method.")

    def hex_to_bytes(self, hash_string):
        """
        Utility method to convert a hexadecimal hash string to bytes.
        """
        try:
            return bytes.fromhex(hash_string)
        except ValueError:
            raise ValueError("Invalid hash format (not hexadecimal)")


class Argon2Handler(HashHandler):
    def parse_hash_digest_with_metadata(self):
        """
        Parses the Argon2 metadata from hash_digest_with_metadata and decodes
        salt and target hashes for each item in the list.
        """
        self.target_hash_to_crack = []  # Reset target hashes

        for hash_digest in self.hash_digest_with_metadata:
            parts = hash_digest.split("$")

            # Parsing logic specific to Argon2
            if len(parts) != 6 or parts[0] != "":
                raise ValueError(f"Invalid Argon2 hash format: {hash_digest}")
            
            version = int(parts[2].split("=")[1])
            param_string = parts[3]
            memory_cost = int(param_string.split(",")[0].split("=")[1])
            time_cost = int(param_string.split(",")[1].split("=")[1])
            parallelism = int(param_string.split(",")[2].split("=")[1])

            # Store the hash and create a PasswordHasher for each entry
            self.target_hash_to_crack.append({
                "full_hash": hash_digest,
                "hash_processor": PasswordHasher(
                    time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism
                ),
            })


    def verify(self, potential_password_match):
        """
        Verifies a potential password against a list of stored Argon2 hashes.
        """
        for entry in self.target_hash_to_crack:
            full_hash = entry["full_hash"]
            hash_processor = entry["hash_processor"]

            try:
                if hash_processor.verify(full_hash, potential_password_match):
                    return potential_password_match.decode()  # Match found
            except Exception:
                # Continue to the next hash if verification fails
                continue

        return None  # No matches found


class ScryptHandler(HashHandler):
    def parse_hash_digest_with_metadata(self):
        """
        Parses the scrypt metadata from hash_digest_with_metadata and decodes
        salt and target hashes for each item in the list.
        """
        self.target_hash_to_crack = []  # Reset target hashes

        for hash_digest in self.hash_digest_with_metadata:
            # Split the hash digest into components
            parts = hash_digest.split("$")
            if len(parts) != 5 or parts[0] != "":
                raise ValueError(f"Invalid scrypt hash format: {hash_digest}")

            # Parse n, r, p parameters
            n = int(parts[2].split("=")[1].split(",")[0])  # Memory cost
            r = int(parts[2].split(",")[1].split("=")[1])  # Block size
            p = int(parts[2].split(",")[2].split("=")[1])  # Parallelism

            # Decode salt and hash
            salt_b64 = parts[3]
            hash_b64 = parts[4]
            salt = base64.urlsafe_b64decode(salt_b64.encode("utf-8"))
            target_hash = base64.urlsafe_b64decode(hash_b64.encode("utf-8"))

            # Store parameters and decoded hashes
            self.target_hash_to_crack.append({
                "n": n,
                "r": r,
                "p": p,
                "salt": salt,
                "target_hash": target_hash
            })

    def verify(self, potential_password_match):
        """
        Verifies a potential password by deriving its Scrypt hash
        and comparing it against each stored hash in target_hash_to_crack.
        """
        for entry in self.target_hash_to_crack:
            # Extract parameters for this hash
            n = entry["n"]
            r = entry["r"]
            p = entry["p"]
            salt = entry["salt"]
            target_hash = entry["target_hash"]

            # Instantiate a new Scrypt KDF
            scrypt_kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
            try:
                # Derive the hash for the potential password
                computed_hash = scrypt_kdf.derive(potential_password_match)

                # Compare computed hash with the target hash
                if computed_hash == target_hash:
                    return potential_password_match.decode()  # Match found
            except Exception as e:
                print(f"Error during verification: {e}")
                continue  # Move to the next hash in case of an error

        return None  # No match found


class PBKDF2Handler(HashHandler):
    def parse_hash_digest_with_metadata(self):
        self.target_hash_to_crack = []

        for hash_digest in self.hash_digest_with_metadata:
            parts = hash_digest.split("$")
            if len(parts) != 5 or parts[0] != "":
                raise ValueError("Invalid PBKDF2 hash format")

            iterations = int(parts[2].split("=")[1])
            salt_b64 = parts[3]
            hash_b64 = parts[4]

            # Decode salt and target hash
            salt = base64.urlsafe_b64decode(salt_b64.encode("utf-8"))
            target_hash = base64.urlsafe_b64decode(hash_b64.encode("utf-8"))

            # Append to the list of hashes to crack
            self.target_hash_to_crack.append({
                "iterations": iterations,
                "salt": salt,
                "target_hash": target_hash
            })

    def verify(self, potential_password_match):
        """
        Verifies a potential password against a list of stored PBKDF2 hashes.
        """
        for entry in self.target_hash_to_crack:
            iterations = entry["iterations"]
            salt = entry["salt"]
            target_hash = entry["target_hash"]

            # Create a new PBKDF2HMAC instance dynamically
            hash_processor = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,
                salt=salt,
                iterations=iterations
            )

            try:
                if hash_processor.derive(potential_password_match) == target_hash:
                    return potential_password_match.decode()  # Match found
            
            except InvalidKey:
                print(f"Password did not match for target hash: {target_hash}")
                continue

        return None  # No matches found


class BcryptHandler(HashHandler):
    def parse_hash_digest_with_metadata(self):
        """Prepare the hashes for comparison."""
        self.target_hash_to_crack = [
            hash_digest.encode("utf-8") for hash_digest in self.hash_digest_with_metadata
        ]

    def verify(self, potential_password_match):
        """Verify if the password matches any target hash."""
        try:
            for hash_digest in self.target_hash_to_crack:
                if bcrypt.checkpw(potential_password_match, hash_digest):
                    return potential_password_match.decode()  # Return on first match
            return None  # No matches found after checking all hashes
        except bcrypt.error as e:
            print(f"Error during bcrypt verification: {e}")
            return None


class NTLMHandler(HashHandler):
    def parse_hash_digest_with_metadata(self):
        """
        Parse the NTLM hash metadata to extract the hash to crack.
        """
        # Example NTLM format: $NTLM$<32-character hash>
        for hash_digest in self.hash_digest_with_metadata:
            parts = hash_digest.split("$")

            # Check if it follows the NTLM format
            if len(parts) == 3 and len(parts[2]) == 32:
                # Proceed with the hash
                self.target_hash_to_crack.append(self.hex_to_bytes(parts[2]))
            else:
                raise ValueError(f"Invalid NTLM hash format: {self.hash_digest_with_metadata}")

    def verify(self, potential_match):
        """
        Verify the password by calculating its NTLM hash and comparing it with the target hashes.
        """
        try:
            # Create the MD4 hash object
            password = potential_match.decode() if isinstance(potential_match, bytes) else potential_match
            ntlm_hash = MD4.new()
            ntlm_hash.update(password.encode('utf-16le'))
            
            # Compare the computed NTLM hash with each hash in the target list
            computed_hash = ntlm_hash.digest()
            # Check if computed_hash matches any in the list
            if computed_hash in self.target_hash_to_crack:
                return password  # Return the matched password
            
            return None  # Return None if no match found
        
        except Exception as e:
            print(f"Error during NTLM hash verification: {e}")
            return None
        

class MD5Handler(HashHandler):
    def parse_hash_digest_with_metadata(self):
        """
        Parse the MD5 hash metadata to extract the hash to crack.
        """
        for hash_digest in self.hash_digest_with_metadata:
            parts = hash_digest.split("$")

            # Check if it follows the NTLM format
            if len(parts) == 3 and len(parts[2]) == 32:
                # Proceed with the hash
                self.target_hash_to_crack.append(self.hex_to_bytes(parts[2]))
            else:
                raise ValueError(f"Invalid MD5 hash format: {self.hash_digest_with_metadata}")

    def verify(self, potential_password_match):
        try:
            password = potential_password_match.decode()
            md5_hash = hashlib.md5(password.encode('utf-8')).digest()
            
            if md5_hash in self.target_hash_to_crack:
                return password  # Return the matched password
            
            return None  # Return None if no match found
            
        except Exception as e:
            print(f"Error during MD5 hash verification: {e}")
            return None


class SHA256Handler(HashHandler):
    def parse_hash_digest_with_metadata(self):
        """
        Parse the SHA-256 hash metadata to extract the hash to crack.
        """
        for hash_digest in self.hash_digest_with_metadata:
            parts = hash_digest.split("$")

            # Check if it follows the NTLM format
            if len(parts) == 3 and len(parts[2]) == 64:
                # Proceed with the hash
                self.target_hash_to_crack.append(self.hex_to_bytes(parts[2]))
            else:
                raise ValueError(f"Invalid SHA-256 hash format: {self.hash_digest_with_metadata}")

    def verify(self, potential_password_match):
        """
        Verify the password by calculating its SHA-256 hash and comparing it.
        """
        try:
            password = potential_password_match.decode()
            sha256_hash = hashlib.sha256(password.encode('utf-8')).digest()
            
            if sha256_hash in self.target_hash_to_crack:
                return password  # Return the matched password
            
            return None  # Return None if no match found
        except Exception as e:
            print(f"Error during SHA-256 hash verification: {e}")
            return None


class SHA512Handler(HashHandler):
    def parse_hash_digest_with_metadata(self):
        """
        Parse the SHA-512 hash metadata to extract the hash to crack.
        """
        # SHA-512 hashes are 128-character hexadecimal strings
        for hash_digest in self.hash_digest_with_metadata:
            parts = hash_digest.split("$")

            # Check if it follows the NTLM format
            if len(parts) == 3 and len(parts[2]) == 128:
                # Proceed with the hash
                self.target_hash_to_crack.append(self.hex_to_bytes(parts[2]))
            else:
                raise ValueError(f"Invalid SHA-512 hash format: {self.hash_digest_with_metadata}")

    def verify(self, potential_password_match):
        """
        Verify the password by calculating its SHA-512 hash and comparing it.
        """
        try:
            password = potential_password_match.decode()
            sha512_hash = hashlib.sha512(password.encode('utf-8')).digest()
                        
            if sha512_hash in self.target_hash_to_crack:
                return password  # Return the matched password
            
            return None  # Return None if no match found
        except Exception as e:
            print(f"Error during SHA-512 hash verification: {e}")
            return None


def get_hash_handler(hash_type, hash_digest_with_metadata):
    hash_handlers = {
        "argon": lambda x: Argon2Handler(x),
        "scrypt": lambda x: ScryptHandler(x),
        "pbkdf2": lambda x: PBKDF2Handler(x),
        "bcrypt": lambda x: BcryptHandler(x),
        "ntlm": lambda x: NTLMHandler(x),
        "md5": lambda x: MD5Handler(x),
        "sha256": lambda x: SHA256Handler(x), 
        "sha512": lambda x: SHA512Handler(x)
    }
    try:
        handler = hash_handlers.get(hash_type)
        
        if not handler:
            raise ValueError(f"No handler found for hash type: {hash_type}")

        return handler(hash_digest_with_metadata)
   
    except ValueError as e:
        raise ValueError(f"Error determining hash type or handler: {e}")

    # CLEAN AF but not as efficient
    # for key, handler in hash_handlers.items():
    #     if key == hash_type:
    #         return handler(hash_digest_with_metadata)


def crack_chunk_wrapper(hash_type, hash_digest_with_metadata, chunk, found_flag):
    return crack_chunk(hash_type, hash_digest_with_metadata, chunk, found_flag)


def crack_chunk(hash_type, hash_digest_with_metadata, chunk, found_flag):
    chunk_count = 0
    if found_flag["found"] >= found_flag["goal"]:
        return False, chunk_count

    hash_handler = get_hash_handler(hash_type, hash_digest_with_metadata)
    hash_handler.parse_hash_digest_with_metadata()

    for potential_password_match in chunk:
        if found_flag["found"] >= found_flag["goal"]:
            return False, chunk_count

        chunk_count += 1
        matched_passwords = hash_handler.verify(potential_password_match)
        if matched_passwords is not None:
            return matched_passwords, chunk_count

    return False, chunk_count