import base64
from argon2 import PasswordHasher
import bcrypt
from Crypto.Hash import MD4
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
        parts = self.hash_digest_with_metadata.split("$")
        # Parsing logic specific to Argon2
        if len(parts) != 6 or parts[0] != "":
            raise ValueError("Invalid Argon2 hash format")
        
        version = int(parts[2].split("=")[1])
        param_string = parts[3]
        memory_cost = int(param_string.split(",")[0].split("=")[1])
        time_cost = int(param_string.split(",")[1].split("=")[1])
        parallelism = int(param_string.split(",")[2].split("=")[1])

        self.target_hash_to_crack = self.hash_digest_with_metadata
        self.hash_processor = PasswordHasher(time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism)

    def verify(self, potential_password_match):
        try:
            return self.hash_processor.verify(self.target_hash_to_crack, potential_password_match)
        except Exception:
            return False


class ScryptHandler(HashHandler):
    def parse_hash_digest_with_metadata(self):
        parts = self.hash_digest_with_metadata.split("$")
        if len(parts) != 5 or parts[0] != "":
            raise ValueError("Invalid scrypt hash format")

        memory_cost = int(parts[2].split("=")[1].split(",")[0])
        block_size = int(parts[2].split(",")[1].split("=")[1])
        parallelism = int(parts[2].split(",")[2].split("=")[1])
        salt_b64 = parts[3]
        hash_b64 = parts[4]

        self.target_hash_to_crack = base64.urlsafe_b64decode(hash_b64.encode("utf-8"))
        self.salt = base64.urlsafe_b64decode(salt_b64.encode("utf-8"))
        self.n = memory_cost
        self.r = block_size
        self.p = parallelism

    def verify(self, potential_password_match):
        # Create a new Scrypt instance for each verification
        scrypt_hash = Scrypt(salt=self.salt, length=32, n=self.n, r=self.r, p=self.p)
        try:
            return scrypt_hash.derive(potential_password_match) == self.target_hash_to_crack
        except Exception:
            return False


class PBKDF2Handler(HashHandler):
    def parse_hash_digest_with_metadata(self):
        for hash_digest in self.hash_digest_with_metadata:
            parts = hash_digest.split("$")
            if len(parts) != 5 or parts[0] != "":
                raise ValueError("Invalid PBKDF2 hash format")

            iterations = int(parts[2].split("=")[1])
            salt_b64 = parts[3]
            hash_b64 = parts[4]

            self.target_hash_to_crack = base64.urlsafe_b64decode(hash_b64.encode("utf-8"))
            self.salt = base64.urlsafe_b64decode(salt_b64.encode("utf-8"))
            self.iterations = iterations

    def verify(self, potential_password_match):
        # Create a new PBKDF2 instance for each verification
        pbkdf2_hash = PBKDF2HMAC(
            algorithm=hashes.SHA512(), length=32, salt=self.salt, iterations=self.iterations
        )
        try:
            return pbkdf2_hash.derive(potential_password_match) == self.target_hash_to_crack
        except Exception:
            return False


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

    def verify(self, potential_password_match):
        """
        Verify the password by calculating its NTLM hash and comparing it with the target hashes.
        """
        try:
            # Create the MD4 hash object
            password = potential_password_match.decode()
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