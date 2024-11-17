import argparse
from pathlib import Path
import yaml


def load_config(config_file=Path ("config.yaml")):
    """
    Load configuration options from a YAML file.
    """
    with open(config_file, "r") as file:
        return yaml.safe_load(file)


def load_args(config=None):
    """
    Parse command-line arguments, optionally overriding with config.
    """
    parser = argparse.ArgumentParser(
        description="Kracker Barrel - Password Hash Cracker",
        epilog="""Examples:
        - Dictionary Attack: python main.py -o dict scrypt hashes.txt wordlist.txt
        - Brute-Force Attack: python main.py -o brut bcrypt hashes.txt --charset "?l?d" --min-length 4 --max-length 6
        - Mask-Based Attack: python main.py -o mask argon hashes.txt --mask "?u?u?d?d?d"
        - Rule-Based Attack: main.py -o rule ntlm hashes.txt --rules rules.txt --wordlist1 wordlist1.txt
        """
    )
    # Mutually exclusive group for operations
    operation_group = parser.add_mutually_exclusive_group(required=True)
    operation_group.add_argument(
        "-d", "--dict",
        action="store_true",
        help="Dictionary attack mode."
    )
    operation_group.add_argument(
        "-b", "--brut",
        action="store_true",
        help="Brute-force attack mode."
    )
    operation_group.add_argument(
        "-m", "--mask",
        action="store_true",
        help="Mask-based attack mode."
    )
    operation_group.add_argument(
        "-r", "--rule",
        action="store_true",
        help="Rule-based attack mode."
    )

    # Common arguments
    parser.add_argument(
        "hash_type",
        nargs="?",
        choices=["argon", "bcrypt", "scrypt", "pbkdf2", "ntlm", "md5", "sha256", "sha512"],
        help="Enter the hash function type you want to crack."
    )
    parser.add_argument(
        "target_file",
        nargs="?",
        help="Enter the hashed password file to crack."
    )
    parser.add_argument(
        "password_list",
        nargs="?",
        help="Enter the file name for dictionary comparison."
    )

    # Arguments specific to brute-force
    parser.add_argument(
        "--charset",
        type=str,
        default="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        help="Charset for brute-force attack (default: alphanumeric)."
    )
    parser.add_argument(
        "--min-length",
        type=int,
        default=1,
        help="Minimum length for brute-force attack (default: 1)."
    )
    parser.add_argument(
        "--max-length",
        type=int,
        default=8,
        help="Maximum length for brute-force attack (default: 8)."
    )

    # Arguments specific to mask-based attack
    parser.add_argument(
        "--mask",
        type=str,
        help="Mask for mask-based attack (e.g., '?l?l?l?d' for four lowercase letters and a digit)."
    )

    # Arguments specific to rule-based attack
    parser.add_argument(
        "--rules",
        type=str,
        help="Path to rule file for rule-based attack."
    )
    parser.add_argument(
        "--wordlist1",
        type=str,
        help="Path to the first wordlist for rule-based attack."
    )
    parser.add_argument(
        "--wordlist2",
        type=str,
        help="Path to the second wordlist for rule-based attack."
    )

    # Parse CLI arguments
    args = parser.parse_args()

    # Map config operation to CLI flags
    if config:
        operation_map = {
            "dict": "dict",
            "brut": "brut",
            "mask": "mask",
            "rule": "rule"
        }
        operation = config.get("operation")
        if operation in operation_map:
            parser.set_defaults(**{operation_map[operation]: True})

        # Set other config values as defaults
        parser.set_defaults(
            hash_type=config.get("hash_type"),
            target_file=config.get("target_file"),
            password_list=config.get("password_list"),
            charset=config.get("charset"),
            min_length=config.get("min_length"),
            max_length=config.get("max_length"),
            mask=config.get("mask"),
            rules=config.get("rules"),
            wordlist1=config.get("wordlist1"),
            wordlist2=config.get("wordlist2"),
        )

    # Re-parse with defaults applied
    return parser.parse_args()