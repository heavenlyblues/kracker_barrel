from argon2 import PasswordHasher
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import bcrypt
import base64


class HashHandler:
    def __init__(self, hash_digest_with_metadata):
        self.hash_digest_with_metadata = hash_digest_with_metadata
        self.target_hash_to_crack = None
        self.hash_processor = None

    def parse_hash_digest_with_metadata(self):
        raise NotImplementedError("Subclasses must implement this method.")

    def verify(self, potential_password_match):
        raise NotImplementedError("Subclasses must implement this method.")
    
    @classmethod
    def get_hash_type(cls, hash_digest_with_metadata):
        parts = hash_digest_with_metadata.split("$")

        if "argon" in parts[1]:
            return "argon"
        elif "scrypt" in parts[1]:
            return "scrypt"
        elif "pbkdf2" in parts[1]:
            return "pbkdf2"
        elif "2b" in parts[1]:
            return "bcrypt"
        else:
            raise ValueError("Unsupported hash type")
        

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
        hash_processor = Scrypt(salt=self.salt, length=32, n=self.n, r=self.r, p=self.p)
        try:
            return hash_processor.derive(potential_password_match) == self.target_hash_to_crack
        except Exception:
            return False


class PBKDF2Handler(HashHandler):
    def parse_hash_digest_with_metadata(self):
        parts = self.hash_digest_with_metadata.split("$")
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
        hash_processor = PBKDF2HMAC(
            algorithm=hashes.SHA512(), length=32, salt=self.salt, iterations=self.iterations
        )
        try:
            return hash_processor.derive(potential_password_match) == self.target_hash_to_crack
        except Exception:
            return False


class BcryptHandler(HashHandler):
    def parse_hash_digest_with_metadata(self):
        self.target_hash_to_crack = self.hash_digest_with_metadata.encode()

    def verify(self, potential_password_match):
        try:
            return bcrypt.checkpw(potential_password_match, self.target_hash_to_crack)
        except Exception:
            return False


def get_hash_handler(hash_digest_with_metadata):
    type_of_hash = HashHandler.get_hash_type(hash_digest_with_metadata)
    if type_of_hash == "argon":
        return Argon2Handler(hash_digest_with_metadata)
    elif type_of_hash == "scrypt":
        return ScryptHandler(hash_digest_with_metadata)
    elif type_of_hash == "pbkdf2":
        return PBKDF2Handler(hash_digest_with_metadata)
    elif type_of_hash == "bcrypt":
        return BcryptHandler(hash_digest_with_metadata)
    else:
        raise ValueError("Unsupported hash type")


def crack_chunk_wrapper(hash_digest_with_metadata, chunk, found_flag):
    return crack_chunk(hash_digest_with_metadata, chunk, found_flag)


def crack_chunk(hash_digest_with_metadata, chunk, found_flag):
    chunk_count = 0
    if found_flag["found"] == 0:
        return False, chunk_count

    hash_handler = get_hash_handler(hash_digest_with_metadata)
    hash_handler.parse_hash_digest_with_metadata()

    for potential_password_match in chunk:
        if found_flag["found"] == 0:
            return False, chunk_count

        chunk_count += 1
        if hash_handler.verify(potential_password_match):
            found_flag["found"] = 0
            return potential_password_match.decode(), chunk_count

    return False, chunk_count