from core.hash_handler import HashHandler


class HashTypeDetector:
    HASH_MAP = {
        "argon2id": "argon",
        "2b": "bcrypt",
        "pbkdf2": "pbkdf2",
        "scrypt": "scrypt",
        "ntlm": "ntlm",
        "md5": "md5",
        "sha256": "sha256",
        "sha512": "sha512",
    }

    @staticmethod
    def detect(hash_metadata: list) -> str:
        """
        Detects the hash type from the provided hash metadata.
        Args:
            hash_metadata: List of hash strings to crack.

        Returns:
            str: The detected hash type.
        """
        try:
            type_check = hash_metadata[0].split("$", 2)[1]
            return HashTypeDetector.HASH_MAP[type_check]
        except (KeyError, IndexError):
            raise ValueError(
                f"Unknown or malformed hash format. Available types: {', '.join(HashTypeDetector.HASH_MAP.keys())}"
            )

    @staticmethod
    def initialize(hash_metadata: list, hash_type: str):
        """
        Initializes the appropriate hash handler for the detected hash type.
        Args:
            hash_metadata: List of hash strings to crack.
            hash_type: The detected hash type.

        Returns:
            A hash handler instance appropriate for the hash type.
        """
        handlers = {
            "argon": HashHandler.Argon2Handler,
            "scrypt": HashHandler.ScryptHandler,
            "pbkdf2": HashHandler.PBKDF2Handler,
            "bcrypt": HashHandler.BcryptHandler,
            "ntlm": HashHandler.NTLMHandler,
            "md5": HashHandler.MD5Handler,
            "sha256": HashHandler.SHA256Handler,
            "sha512": HashHandler.SHA512Handler,
        }
        try:
            return handlers[hash_type](hash_metadata)
        except KeyError:
            raise ValueError(
                f"No handler available for hash type: {hash_type}. Supported types: {', '.join(handlers.keys())}"
            )