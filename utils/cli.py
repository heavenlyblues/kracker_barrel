import argparse


PURPLE, RESET = "\033[0;35m", "\033[0m"


def get_command_line_args():
    parser = argparse.ArgumentParser(description=f"{PURPLE}KRACKER BARREL{RESET}")
    
    parser.add_argument(
        "-o", "--operation", 
        required=True, 
        choices=["dict", "brut", "mask", "rule"], 
        help="Recovery strategy to use (dictionary, brute-force, mask, or rule-based)"
    )
    parser.add_argument(
        "target_file", 
        type=str, 
        help="Enter the hashed password file to crack."
    )
    parser.add_argument(
        "hash_type", 
        choices=["argon", "bcrypt", "scrypt", "pbkdf2", 
                 "ntlm", "md5", "sha256", "sha512"], 
        help="Enter the hash function type you want to crack."
    )
    parser.add_argument(
        "--mask",
        type=str,
        help="Mask for mask-based attack (e.g., '?l?l?l?d' for four lowercase letters and a digit)."
    )
    parser.add_argument(
        "--rules",
        type=str,
        help="Path to rule file for rule-based attack."
    )
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

    args = parser.parse_args()

    return args     # Returns -> Namespace(operation='dict', input_file='passwords.txt', hash_type='bcrypt')