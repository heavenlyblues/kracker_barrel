import base64
from argon2 import PasswordHasher
import bcrypt
from Crypto.Hash import MD4
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import hashlib
import logging


class HashHandler:
    # Define a mapping of algorithm names to their respective hash objects
    ALGORITHM_MAP = {
        "sha512": hashes.SHA512,
        "sha256": hashes.SHA256,
        "sha1": hashes.SHA1,
        # Add more algorithms as needed
    }

    def __init__(self, hash_digest_with_metadata):
        self.hash_digest_with_metadata = hash_digest_with_metadata
        self.target_hash_to_crack = []
        self.parameters = []

    def parse_algorithm(self, algorithm_name):
        """
        Dynamically parse and return the hash algorithm object based on its name.
        """
        algorithm_name = algorithm_name.lower()  # Ensure case-insensitivity
        algorithm_class = self.ALGORITHM_MAP.get(algorithm_name)
        if not algorithm_class:
            raise ValueError(f"Unsupported algorithm: {algorithm_name}")
        return algorithm_class()

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
        
    def log_parameters(self):
        raise NotImplementedError("Subclasses must implement this method.")


class Argon2Handler(HashHandler):
    def __init__(self, hash_digest_with_metadata):
        self.hash_digest_with_metadata = set(hash_digest_with_metadata)
        self.parameters = self.parse_hash_digest_with_metadata()
        self.precomputed_processors = self.precompute_processors()


    def parse_hash_digest_with_metadata(self):
        """
        Parses the Argon2 metadata from hash_digest_with_metadata and decodes
        salt and target hashes for each item in the list.
        Format: $argon2id$v=19$m=47104,t=1,p=1$<base64-encoded-salt>$<base64-encoded-hash>
        """
        parameters = []  # Store parsed parameters for each hash

        for hash_digest in self.hash_digest_with_metadata:
            parts = hash_digest.split("$")

            # Validate basic structure of the hash
            if len(parts) != 6:
                raise ValueError(f"Invalid Argon2id hash format: {hash_digest}")

            try:
                algorithm = parts[1]
                version = int(parts[2].split("=")[1])

                # Parse parameters into a dictionary
                param_string = parts[3]
                param_dict = dict(param.split("=") for param in param_string.split(","))

                # Extract memory cost, time cost, and parallelism
                memory_cost = int(param_dict.get("m", 0))
                time_cost = int(param_dict.get("t", 0))
                parallelism = int(param_dict.get("p", 0))

                parameters.append({
                    "algorithm": algorithm,
                    "version": version,
                    "memory_cost": memory_cost,
                    "time_cost": time_cost,
                    "parallelism": parallelism,
                })
            except (ValueError, KeyError) as e:
                raise ValueError(f"Error parsing Argon2 parameters: {hash_digest} - {e}")

        return parameters

    def log_parameters(self):
        """
        Return a formatted log message for parameters. Assumes consistent
        parameters across all hashes.
        """
        first_entry = self.parameters[0]
        return (
            f"version={first_entry['version']}, memory_cost={first_entry['memory_cost']},"
            f" time_cost={first_entry['time_cost']}, parallelism={first_entry['parallelism']}"
        )
    
    def precompute_processors(self):
        """
        Precomputes reusable PasswordHasher instances for each target hash.
        Returns a list of precomputed processors.
        """
        precomputed_processors = []

        for entry in self.parameters:
            precomputed_processors.append(
                PasswordHasher(
                time_cost=entry["time_cost"],
                memory_cost=entry["memory_cost"],
                parallelism=entry["parallelism"]
            ))

        return precomputed_processors
    
    def verify(self, potential_password_match):
        """
        Verifies a potential password against the precomputed processors.
        """
        for target_hash, processor in zip(self.hash_digest_with_metadata, self.precomputed_processors):
            try:
                # Derive the hash and compare with the target
                pwd_encoded = potential_password_match.encode()
                if processor.verify(target_hash, pwd_encoded):
                    return potential_password_match  # Match found
            except Exception:
                # Continue to the next hash if verification fails
                continue

        return None  # No matches found


class ScryptHandler(HashHandler):
    def __init__(self, hash_digest_with_metadata):
        self.hash_digest_with_metadata = hash_digest_with_metadata
        self.parameters = self.parse_hash_digest_with_metadata()

    def parse_hash_digest_with_metadata(self):
        """
        Parses the scrypt metadata from hash_digest_with_metadata and decodes
        salt and target hashes for each item in the list.
        """
        parameters = []  # Store parsed parameters for each hash

        for hash_digest in self.hash_digest_with_metadata:
            # Split the hash digest into components
            parts = hash_digest.split("$")
            if len(parts) != 5 or not parts[1] == "scrypt":
                raise ValueError(f"Invalid scrypt hash format: {hash_digest}")

            try:
                # Parse parameters into a dictionary
                algorithm = parts[1]
                param_string = parts[2]
                param_dict = dict(param.split("=") for param in param_string.split(","))
                
                # Extract memory cost, block size, and parallelism
                n = int(param_dict.get("n", 0))  # Default to 0 if missing
                r = int(param_dict.get("r", 0))
                p = int(param_dict.get("p", 0))

                # Validate parameters
                if not (n > 0 and r > 0 and p > 0):
                    raise ValueError("Scrypt parameters must be positive integers")

                # Decode salt and hash
                salt_b64 = parts[3]
                hash_hex = parts[4]

                salt = base64.urlsafe_b64decode(salt_b64)
                target_hash = bytes.fromhex(hash_hex)

                # Calculate lengths
                hash_length = len(target_hash)
                salt_length = len(salt)

                # Store all parameters in the list
                parameters.append({
                    "algorithm": algorithm,
                    "full_hash": hash_digest,
                    "n": n,
                    "r": r,
                    "p": p,
                    "hash_length": hash_length,
                    "salt_length": salt_length,
                    "salt": salt,
                    "target_hash": target_hash,
                })
            except (ValueError, KeyError) as e:
                raise ValueError(f"Error parsing Scrypt parameters: {hash_digest} - {e}")

        return parameters

    def log_parameters(self):
        """
        Return a formatted log message for parameters. Assumes consistent parameters
        across all hashes for simplicity.
        """
        # Extract the first parameter set for logging (assumes consistent parameters across hashes)
        first_entry = self.parameters[0]
        return (
            f"hash length={first_entry['hash_length']}, "
            f"salt length={first_entry['salt_length']}, n={first_entry['n']}, "
            f"r={first_entry['r']}, parallelism={first_entry['p']}"
        )
    
    def verify(self, potential_password_match):
        """
        Verifies a potential password by deriving its Scrypt hash
        and comparing it against each stored hash in target_hash_to_crack.
        """
        for entry in self.parameters:
            # Extract parameters for this hash
            n = entry["n"]
            r = entry["r"]
            p = entry["p"]
            length = entry["length"]
            salt = entry["salt"]
            target_hash = entry["target_hash"]

            # Instantiate a new Scrypt KDF
            scrypt_kdf = Scrypt(salt=salt, length=length, n=n, r=r, p=p)
            try:
                # Derive the hash for the potential password
                computed_hash = scrypt_kdf.derive(potential_password_match)

                if computed_hash == target_hash:
                    return potential_password_match.decode()  # Match found
            except Exception as e:
                print(f"Error during verification: {e}")
                continue  # Move to the next hash in case of an error

        return None  # No match found


class PBKDF2Handler(HashHandler):
    def __init__(self, hash_digest_with_metadata):
        self.hash_digest_with_metadata = hash_digest_with_metadata
        self.parameters = self.parse_hash_digest_with_metadata()

    def parse_hash_digest_with_metadata(self):
        """
        Parses the PBKDF2 metadata from hash_digest_with_metadata and decodes
        salt and target hashes for each item in the list.
        """
        parameters = []  # Store parsed parameters for each hash

        for hash_digest in self.hash_digest_with_metadata:
            # Split the hash digest into components
            parts = hash_digest.split("$")
            if len(parts) != 5 or parts[1] != "pbkdf2":
                raise ValueError(f"Invalid PBKDF2 hash format: {hash_digest}")

            try:
                # Parse parameters into a dictionary
                param_string = parts[2]
                param_dict = dict(param.split("=") for param in param_string.split(","))

                # Decode salt and hash
                salt_b64 = parts[3]
                hash_hex = parts[4]

                salt = base64.urlsafe_b64decode(salt_b64)
                target_hash = bytes.fromhex(hash_hex)

                # Calculate lengths
                hash_length = len(target_hash)
                salt_length = len(salt)

                # Determine algorithm based on hash length if "a" is not provided
                algorithm = param_dict.get("a", None)
                if not algorithm:
                    if hash_length == 32:
                        algorithm = "sha256"
                    elif hash_length == 64:
                        algorithm = "sha512"
                    else:
                        raise ValueError(f"Unknown algorithm for hash length: {hash_length}")

                # Extract iterations
                iterations = int(param_dict.get("i", 0))  # Iterations count
                if not iterations > 0:
                    raise ValueError("PBKDF2 iterations must be a positive integer")

                # Store all parameters in the list
                parameters.append({
                    "full_hash": hash_digest,
                    "algorithm": algorithm,
                    "iterations": iterations,
                    "hash_length": hash_length,
                    "salt_length": salt_length,
                    "salt": salt,
                    "target_hash": target_hash,
                })
            except (ValueError, KeyError) as e:
                raise ValueError(f"Error parsing PBKDF2 parameters: {hash_digest} - {e}")

        return parameters

    def log_parameters(self):
        """Return a formatted log message for parameters."""
        first_entry = self.parameters[0]
        return (
            f"{first_entry['algorithm']} - iterations={first_entry['iterations']}, "
            f"hash_length={first_entry['hash_length']}, salt_length={first_entry['salt_length']}"
            for entry in self.parameters
        )

    def verify(self, potential_password_match):
        """
        Verifies a potential password against a list of stored PBKDF2 hashes.
        """
        for entry in self.parameters:
            algorithm_name = entry["algorithm"]
            hash_length = entry["hash_length"]
            iterations = entry["iterations"]
            salt = entry["salt"]
            target_hash = entry["target_hash"]

            algorithm = self.parse_algorithm(algorithm_name)

            # Create a new PBKDF2HMAC instance dynamically
            hash_processor = PBKDF2HMAC(
                algorithm=algorithm,
                length=hash_length,
                salt=salt,
                iterations=iterations
            )

            try:
                if hash_processor.derive(potential_password_match) == target_hash:
                    return potential_password_match.decode()  # Match found

            except InvalidKey:
                continue  # Continue to the next entry

        return None  # No matches found
    

# class PBKDF2Handler(HashHandler):
#     def __init__(self, hash_digest_with_metadata):
#         self.hash_digest_with_metadata = hash_digest_with_metadata
#         self.parameters = self.parse_hash_digest_with_metadata()

#     def parse_hash_digest_with_metadata(self):
#         """
#         Parses the PBKDF2 metadata from hash_digest_with_metadata and decodes
#         salt and target hashes for each item in the list.
#         """
#         self.target_hash_to_crack = []  # Reset target hashes

#         for hash_digest in self.hash_digest_with_metadata:
#             # Split the hash digest into components
#             parts = hash_digest.split("$")
#             if len(parts) != 5 or parts[1] != "pbkdf2":
#                 raise ValueError(f"Invalid PBKDF2 hash format: {hash_digest}")

#             try:
#                 # Parse parameters into a dictionary
#                 param_string = parts[2]
#                 param_dict = dict(param.split("=") for param in param_string.split(","))

#                 # Decode salt and hash
#                 salt_b64 = parts[3]
#                 hash_hex = parts[4]

#                 salt = base64.urlsafe_b64decode(salt_b64)
#                 target_hash = bytes.fromhex(hash_hex)

#                 # Calculate lengths
#                 hash_length = len(target_hash)
#                 salt_length = len(salt)

#                 # Determine algorithm based on hash length if "a" is not provided
#                 algorithm = param_dict.get("a", None)
#                 if not algorithm:
#                     if hash_length == 32:
#                         algorithm = "sha256"
#                     elif hash_length == 64:
#                         algorithm = "sha512"
#                     else:
#                         raise ValueError(f"Unknown algorithm for hash length: {hash_length}")

#                 # Extract iterations
#                 iterations = int(param_dict.get("i", 0))  # Iterations count
#                 if not iterations > 0:
#                     raise ValueError("PBKDF2 iterations must be a positive integer")

#                 # Store parameters and decoded hashes
#                 self.target_hash_to_crack.append({
#                     "full_hash": hash_digest,
#                     "algorithm": algorithm,
#                     "iterations": iterations,
#                     "hash_length": hash_length,
#                     "salt": salt,
#                     "target_hash": target_hash,
#                 })
#             except (ValueError, KeyError) as e:
#                 raise ValueError(f"Error parsing PBKDF2 parameters: {hash_digest} - {e}")

#         # Return the parsed parameters for logging or further use
#         return algorithm, iterations, hash_length, salt_length

#     def log_parameters(self):
#         """Return a formatted log message for parameters."""
#         algorithm, length, salt_length, iterations = self.parameters
#         return (
#             f"algorithm={algorithm}, hash length={length}, "
#             f"salt length={salt_length}, iterations={iterations}"
#         )

#     def verify(self, potential_password_match):
#         """
#         Verifies a potential password against a list of stored PBKDF2 hashes.
#         """
#         for entry in self.target_hash_to_crack:
#             algorithm_name = entry["algorithm"]
#             hash_length = entry["hash_length"]
#             iterations = entry["iterations"]
#             salt = entry["salt"]
#             target_hash = entry["target_hash"]

#             algorithm = self.parse_algorithm(algorithm_name)

#             # Create a new PBKDF2HMAC instance dynamically
#             self.hash_processor = PBKDF2HMAC(
#                 algorithm=algorithm,
#                 length=hash_length,
#                 salt=salt,
#                 iterations=iterations
#             )

#             try:
#                 if self.hash_processor.derive(potential_password_match) == target_hash:
#                     return potential_password_match.decode()  # Match found
            
#             except InvalidKey:
#                 print(f"Password did not match for target hash: {target_hash}")
#                 continue

#         return None  # No matches found


class BcryptHandler(HashHandler):
    def __init__(self, hash_digest_with_metadata):
        self.hash_digest_with_metadata = hash_digest_with_metadata
        self.parameters = self.parse_hash_digest_with_metadata()

    def parse_hash_digest_with_metadata(self):
        """
        Parses the bcrypt metadata from hash_digest_with_metadata and returns parameters.
        """
        parameters = []  # Store parsed parameters for each hash

        for hash_digest in self.hash_digest_with_metadata:
            params = hash_digest.split("$")
            if len(params) != 4:
                raise ValueError(f"Invalid bcrypt hash format: {hash_digest}")

            # Extract version and rounds
            version = params[1]
            rounds = int(params[2])

            # Store all parameters for each hash
            parameters.append({
                "full_hash": hash_digest.encode("utf-8"),
                "version": version,
                "rounds": rounds
            })

        return parameters

    def log_parameters(self):
        """
        Logs the first bcrypt hash's version and rounds for reference.
        """
        # Assuming all hashes have the same version and rounds
        first_entry = self.parameters[0]
        return f"version={first_entry['version']}, rounds={first_entry['rounds']}"

    def verify(self, potential_password_match):
        """
        Verifies a potential password against the stored bcrypt hashes.
        """
        try:
            for entry in self.parameters:
                target_hash = entry["full_hash"]
                # Use bcrypt's checkpw function to verify the password
                if bcrypt.checkpw(potential_password_match.encode("utf-8"), target_hash):
                    return potential_password_match  # Return on first match
            return None  # No matches found after checking all hashes
        except bcrypt.error as e:
            print(f"Error during bcrypt verification: {e}")
            return None


class NTLMHandler(HashHandler):
    def __init__(self, hash_digest_with_metadata):
        self.hash_digest_with_metadata = hash_digest_with_metadata
        self.parameters = self.parse_hash_digest_with_metadata()

    def parse_hash_digest_with_metadata(self):
        """
        Parse the NTLM hash metadata and extract relevant parameters.
        """
        parameters = []  # Store parsed parameters for each hash
        
        # Example NTLM format: $NTLM$<32-character hash>
        for hash_digest in self.hash_digest_with_metadata:
            parts = hash_digest.split("$")
            
            if len(parts) == 3 and len(parts[2]) == 32:
                target_hash = self.hex_to_bytes(parts[2])  # Convert hex to bytes
                parameters.append({
                    "full_hash": hash_digest,
                    "target_hash": target_hash,
                    "hash_func": "MD4",
                    "encoding": "UTF-16LE",
                    "length": len(parts[2])
                })
            else:
                raise ValueError(f"Invalid NTLM hash format: {hash_digest}")
        
        return parameters

    def log_parameters(self):
        """
        Log the underlying algorithm, encoding, and hash length.
        Assumes uniform parameters for all hashes.
        """
        first_entry = self.parameters[0]  # Use the first hash for metadata
        return (
            f"underlying algorithm={first_entry['hash_func']}, "
            f"encoding={first_entry['encoding']}, "
            f"hash length={first_entry['length']}"
        )

    def verify(self, potential_password_match):
        """
        Verify the password by calculating its NTLM hash and comparing it with the target hashes.
        """
        try:
            # Convert potential password match to string if needed
            password = (
                potential_password_match.decode()
                if isinstance(potential_password_match, bytes)
                else potential_password_match
            )

            # Compute NTLM hash for the password
            ntlm_hash = MD4.new()
            ntlm_hash.update(password.encode("utf-16le"))
            computed_hash = ntlm_hash.digest()

            # Check if the computed hash matches any target hash
            for entry in self.parameters:
                if computed_hash == entry["target_hash"]:
                    return password  # Return the matched password
            
            return None  # Return None if no match found
        except Exception as e:
            print(f"Error during NTLM hash verification: {e}")
            return None

    @staticmethod
    def hex_to_bytes(hex_string):
        """
        Convert a hex string to bytes.
        """
        return bytes.fromhex(hex_string)


class MD5Handler(HashHandler):
    def __init__(self, hash_digest_with_metadata):
        self.hash_digest_with_metadata = hash_digest_with_metadata
        self.parameters = self.parse_hash_digest_with_metadata()

    def parse_hash_digest_with_metadata(self):
        """
        Parse the MD5 hash metadata to extract the hash to crack.
        """
        self.target_hash_to_crack = []  # Reset target hashes

        for hash_digest in self.hash_digest_with_metadata:
            parts = hash_digest.split("$")

            # Check if it follows the NTLM format
            if len(parts) == 3 and len(parts[2]) == 32:
                # Proceed with the hash
                self.target_hash_to_crack.append(self.hex_to_bytes(parts[2]))
            else:
                raise ValueError(f"Invalid MD5 hash format: {self.hash_digest_with_metadata}")
        return "UTF-8", len(parts[2])
    
    def log_parameters(self):
        """Return a formatted log message for parameters."""
        encoding, format = self.parameters
        return (
            f"encoding={encoding}, hash format={format * 4} bits ({int(format / 2)} bytes), {format}-character hexadecimal string"
        )
    
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
    def __init__(self, hash_digest_with_metadata):
        self.hash_digest_with_metadata = hash_digest_with_metadata
        self.parameters = self.parse_hash_digest_with_metadata()

    def parse_hash_digest_with_metadata(self):
        """
        Parse the SHA-256 hash metadata to extract the hash to crack.
        """
        self.target_hash_to_crack = []  # Reset target hashes

        for hash_digest in self.hash_digest_with_metadata:
            parts = hash_digest.split("$")

            # Check if it follows the NTLM format
            if len(parts) == 3 and len(parts[2]) == 64:
                # Proceed with the hash
                self.target_hash_to_crack.append(self.hex_to_bytes(parts[2]))
            else:
                raise ValueError(f"Invalid SHA-256 hash format: {self.hash_digest_with_metadata}")
            
            return "UTF-8", len(parts[2])

            
    def log_parameters(self):
        """Return a formatted log message for parameters."""
        encoding, format = self.parameters
        return (
            f"encoding={encoding}, hash format={format * 4} bits ({int(format / 2)} bytes), {format}-character hexadecimal string"
        )
    
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
    def __init__(self, hash_digest_with_metadata):
        self.hash_digest_with_metadata = hash_digest_with_metadata
        self.parameters = self.parse_hash_digest_with_metadata()

    def parse_hash_digest_with_metadata(self):
        """
        Parse the SHA-512 hash metadata to extract the hash to crack.
        """
        self.target_hash_to_crack = []  # Reset target hashes

        # SHA-512 hashes are 128-character hexadecimal strings
        for hash_digest in self.hash_digest_with_metadata:
            parts = hash_digest.split("$")

            # Check if it follows the NTLM format
            if len(parts) == 3 and len(parts[2]) == 128:
                # Proceed with the hash
                self.target_hash_to_crack.append(self.hex_to_bytes(parts[2]))
            else:
                raise ValueError(f"Invalid SHA-512 hash format: {self.hash_digest_with_metadata}")
            
            return "UTF-8", len(parts[2])

            
    def log_parameters(self):
        """Return a formatted log message for parameters."""
        encoding, format = self.parameters
        return (
            f"encoding={encoding}, hash format={format * 4} bits ({int(format / 2)} bytes), {format}-character hexadecimal string"
        )
    
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


# Assign handlers to HashHandler dynamically
HashHandler.Argon2Handler = Argon2Handler
HashHandler.ScryptHandler = ScryptHandler
HashHandler.PBKDF2Handler = PBKDF2Handler
HashHandler.BcryptHandler = BcryptHandler
HashHandler.NTLMHandler = NTLMHandler
HashHandler.MD5Handler = MD5Handler
HashHandler.SHA256Handler = SHA256Handler
HashHandler.SHA512Handler = SHA512Handler


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
    

def crack_chunk_wrapper(hash_type, hash_digest_with_metadata, chunk, found_flag):
    return crack_chunk(hash_type, hash_digest_with_metadata, chunk, found_flag)


def crack_chunk(hash_type, hash_digest_with_metadata, chunk, found_flag):
    chunk_count = 0
    results = []  # Collect all matches

    if found_flag["found"] >= found_flag["goal"]:
        return results, chunk_count
    
    hash_handler = get_hash_handler(hash_type, hash_digest_with_metadata)
    hash_handler.parse_hash_digest_with_metadata()

    for potential_password_match in chunk:
        # print(f"Testing: {potential_password_match}")
        if found_flag["found"] >= found_flag["goal"]:
            return results, chunk_count

        chunk_count += 1
        matched_passwords = hash_handler.verify(potential_password_match)
        if matched_passwords is not None:
            results.append(matched_passwords)  # Collect matches in the list
    
    return results, chunk_count  # Return all matches at once