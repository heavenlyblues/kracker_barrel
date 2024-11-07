from argon2 import PasswordHasher
import bcrypt
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def create_hash_function(hash_func, salt, test_mode):
    """Create a hashing object based on the specified hash algorithm and test mode."""
    if hash_func == "argon":
        return PasswordHasher(
            time_cost=1 if test_mode else 3, 
            memory_cost=2**10 if test_mode else 12288, 
            parallelism=1
        )
    elif hash_func == "scrypt":
        return Scrypt(
            salt=salt, length=32, 
            n=2**8 if test_mode else 2**14, 
            r=18 if test_mode else 8, 
            p=1 if test_mode else 5
        )
    elif hash_func == "pbkdf2":
        return PBKDF2HMAC(
            algorithm=hashes.SHA512(), 
            length=32, salt=salt, 
            iterations=1000 if test_mode else 210000
        )
    return None  # bcrypt is handled directly without helper function

def verify_password(hash_func, target_hash, known_password, salt, test_mode):
    """
    Verify if a known_password matches the target hash using the specified hash_func.
    Returns True if there's a match, False otherwise.
    """
    hash_object = None
    
    if hash_func == "argon":
        hash_object = create_hash_function("argon", salt, test_mode)
        return hash_object.verify(target_hash, known_password)

    elif hash_func == "bcrypt":
        return bcrypt.checkpw(known_password, target_hash)

    elif hash_func == "scrypt":
        hash_object = create_hash_function("scrypt", salt, test_mode)
        return hash_object.derive(known_password) == target_hash

    elif hash_func == "pbkdf2":
        hash_object = create_hash_function("pbkdf2", salt, test_mode)
        return hash_object.derive(known_password) == target_hash

    return False