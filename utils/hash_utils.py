from argon2 import PasswordHasher
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import bcrypt
import base64


class HashHandler:
    def __init__(self, hash_string):
        self.hash_string = hash_string
        self.target_hash = None
        self.hash_object = None

    def parse_hash_string(self):
        raise NotImplementedError("Subclasses must implement this method.")

    def verify(self, password):
        raise NotImplementedError("Subclasses must implement this method.")
    
    @classmethod
    def get_hash_flag(cls, hash_string):
        parts = hash_string.split("$")

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
    def parse_hash_string(self):
        parts = self.hash_string.split("$")
        # Parsing logic specific to Argon2
        if len(parts) != 6 or parts[0] != "":
            raise ValueError("Invalid Argon2 hash format")
        
        version = int(parts[2].split("=")[1])
        param_string = parts[3]
        memory_cost = int(param_string.split(",")[0].split("=")[1])
        time_cost = int(param_string.split(",")[1].split("=")[1])
        parallelism = int(param_string.split(",")[2].split("=")[1])

        self.target_hash = self.hash_string
        self.hash_object = PasswordHasher(time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism)

    def verify(self, password):
        try:
            return self.hash_object.verify(self.target_hash, password)
        except Exception:
            return False


class ScryptHandler(HashHandler):
    def parse_hash_string(self):
        parts = self.hash_string.split("$")
        if len(parts) != 5 or parts[0] != "":
            raise ValueError("Invalid scrypt hash format")

        n = int(parts[2].split("=")[1].split(",")[0])
        r = int(parts[2].split(",")[1].split("=")[1])
        p = int(parts[2].split(",")[2].split("=")[1])
        salt_b64 = parts[3]
        hash_b64 = parts[4]

        self.target_hash = base64.urlsafe_b64decode(hash_b64.encode("utf-8"))
        self.salt = base64.urlsafe_b64decode(salt_b64.encode("utf-8"))
        self.n = n
        self.r = r
        self.p = p

    def verify(self, password):
        # Create a new Scrypt instance for each verification
        hash_object = Scrypt(salt=self.salt, length=32, n=self.n, r=self.r, p=self.p)
        try:
            return hash_object.derive(password) == self.target_hash
        except Exception:
            return False


class PBKDF2Handler(HashHandler):
    def parse_hash_string(self):
        parts = self.hash_string.split("$")
        if len(parts) != 5 or parts[0] != "":
            raise ValueError("Invalid PBKDF2 hash format")

        iterations = int(parts[2].split("=")[1])
        salt_b64 = parts[3]
        hash_b64 = parts[4]

        self.target_hash = base64.urlsafe_b64decode(hash_b64.encode("utf-8"))
        self.salt = base64.urlsafe_b64decode(salt_b64.encode("utf-8"))
        self.iterations = iterations

    def verify(self, password):
        # Create a new PBKDF2 instance for each verification
        hash_object = PBKDF2HMAC(
            algorithm=hashes.SHA512(), length=32, salt=self.salt, iterations=self.iterations
        )
        try:
            return hash_object.derive(password) == self.target_hash
        except Exception:
            return False


class BcryptHandler(HashHandler):
    def parse_hash_string(self):
        self.target_hash = self.hash_string.encode()

    def verify(self, password):
        try:
            return bcrypt.checkpw(password, self.target_hash)
        except Exception:
            return False
        

def get_hash_handler(hash_string):
    flag = HashHandler.get_hash_flag(hash_string)
    if flag == "argon":
        return Argon2Handler(hash_string)
    elif flag == "scrypt":
        return ScryptHandler(hash_string)
    elif flag == "pbkdf2":
        return PBKDF2Handler(hash_string)
    elif flag == "bcrypt":
        return BcryptHandler(hash_string)
    else:
        raise ValueError("Unsupported hash type")

def crack_chunk_wrapper(hash_string, chunk, flag):
    return crack_chunk(hash_string, chunk, flag)

def crack_chunk(hash_string, chunk, flag):
    chunk_count = 0
    if flag["found"] == 0:
        return False, chunk_count

    hash_handler = get_hash_handler(hash_string)
    hash_handler.parse_hash_string()

    for known_password in chunk:
        if flag["found"] == 0:
            return False, chunk_count

        chunk_count += 1
        if hash_handler.verify(known_password):
            flag["found"] = 0
            return known_password.decode(), chunk_count

    return False, chunk_count