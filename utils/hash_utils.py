import base64
from argon2 import PasswordHasher
import bcrypt
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Wrapper function to pass crack chunk function into 'executor.submit' method.
# Allows for structured argument passing into attempt_crack.
def crack_chunk_wrapper(hash_string, chunk, flags):
    return crack_chunk(hash_string, chunk, flags)


# Gets the flag for crack_chunk()
def get_hash_flag(hash_string):
    parts = hash_string.split("$")

    if "argon" in parts[1]:
        hash_func_flag = "argon"
    elif "scrypt" in parts[1]:
        hash_func_flag = "scrypt"
    elif "pbkdf2" in parts[1]:
        hash_func_flag = "pbkdf2"
    else:
        hash_func_flag = "bcrypt"
    return hash_func_flag


def crack_chunk(hash_string, chunk, flags):
    """Process a chunk of passwords to find a match for the target hash."""
    if flags["found"]:
        return False, 0  # Exit if the password has been found elsewhere

    hash_flag = get_hash_flag(hash_string)

    if hash_flag == "argon":
        target_hash, reusable_hash_object = create_hash_function(hash_string)
    if hash_flag == "bcrypt":
        target_hash = hash_string.encode()
    
    chunk_count = 0

    for known_password in chunk:
        if flags["found"]:
            return False, chunk_count
        
        chunk_count += 1
        
        # if chunk_count % 1000 == 0:
        #     print(f"Batch processing... {known_password.decode()}")
        
        try:
            # Check for Argon2
            if hash_flag == "argon" and reusable_hash_object.verify(target_hash, known_password):
                flags["found"] = True
                return known_password.decode(), chunk_count

            # Check for bcrypt
            elif hash_flag == "bcrypt":
                if bcrypt.checkpw(known_password, target_hash):
                    flags["found"] = True
                    return known_password.decode(), chunk_count

            # Check for Scrypt
            elif hash_flag == "scrypt":
                target_hash, hash_object = create_hash_function(hash_string)
                if hash_object.derive(known_password) == target_hash:
                    flags["found"] = True
                    return known_password.decode(), chunk_count

            # Check for PBKDF2
            elif hash_flag == "pbkdf2":
                target_hash, hash_object = create_hash_function(hash_string)
                if hash_object.derive(known_password) == target_hash:
                    flags["found"] = True
                    return known_password.decode(), chunk_count

        except Exception as e:
            # Handle exceptions without affecting count tracking
            pass

    return False, chunk_count


def create_hash_function(hash_string):
    """Create a hashing object based on the specified hash algorithm from hash_string."""
    parts = hash_string.split("$")

    if "argon" in parts[1]:
        # Expected format: $argon2id$v=19$m=1024,t=1,p=1$salt$hash
        if len(parts) != 6 or parts[0] != "":
            raise ValueError("Invalid Argon2 hash format")

        try:
            # Parse the version
            version = int(parts[2].split("=")[1])

            # Parse memory, time, and parallelism values individually
            param_string = parts[3]  # m=1024,t=1,p=1
            memory_cost = int(param_string.split(",")[0].split("=")[1])  # m=1024
            time_cost = int(param_string.split(",")[1].split("=")[1])  # t=1
            parallelism = int(param_string.split(",")[2].split("=")[1])  # p=1

            # Decode the salt and target hash, ensuring padding
            target_hash = hash_string

        except (IndexError, ValueError) as e:
            raise ValueError(f"Error parsing Argon2 hash string: {e}")

        # Return the target_hash and PasswordHasher instance
        return target_hash, PasswordHasher(
            time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism
        )

    elif "scrypt" in parts[1]:
        # Expected format: $scrypt$ln=16384,r=8,p=1$salt$hash
        if len(parts) != 5 or parts[0] != "":
            raise ValueError("Invalid scrypt hash format")

        # Parse parameters
        n = int(parts[2].split("=")[1].split(",")[0])
        r = int(parts[2].split(",")[1].split("=")[1])
        p = int(parts[2].split(",")[2].split("=")[1])
        salt_b64 = parts[3]
        hash_b64 = parts[4]

        # Decode salt and target hash
        salt = base64.urlsafe_b64decode(salt_b64.encode("utf-8"))
        target_hash = base64.urlsafe_b64decode(hash_b64.encode("utf-8"))

        # Return target_hash and scrypt KDF instance
        return target_hash, Scrypt(salt=salt, length=32, n=n, r=r, p=p)

    elif "pbkdf2" in parts[1]:
        # Expected format: $pbkdf2_sha512$iterations=210000$salt$hash
        if len(parts) != 5 or parts[0] != "":
            raise ValueError("Invalid PBKDF2 hash format")

        # Parse parameters
        iterations = int(parts[2].split("=")[1])
        salt_b64 = parts[3]
        hash_b64 = parts[4]

        # Decode salt and target hash
        salt = base64.urlsafe_b64decode(salt_b64.encode("utf-8"))
        target_hash = base64.urlsafe_b64decode(hash_b64.encode("utf-8"))

        # Return target_hash and PBKDF2 KDF instance
        return target_hash, PBKDF2HMAC(
            algorithm=hashes.SHA512(), length=32, salt=salt, iterations=iterations
        )

    else:
        raise ValueError("Unsupported hash function")