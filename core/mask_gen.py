import functools
import itertools


MASK_MAP = {
    "?u":   "ABCDEFGHIJKLMNOPQRSTUVWXYZ",       # Uppercase letters
    "?u+":  "ABCDEFGHIJKLMNOPQRSTUVWXYZÅÄÖÉ",   # Uppercase letters Swedish
    "?l":   "abcdefghijklmnopqrstuvwxyz",       # Lowercase letters
    "?l+":  "abcdefghijklmnopqrstuvwxyzåäöé",   # Lowercase letters Swedish
    "?d":   "0123456789",                       # Digits
    "?s+":   "!@#$%^&*()-_=+[]{}|;:',.<>?/`~",  # Special characters
    "?s":   "!@#$%^&*()-_=+",                   # Abridged special characters
    "?p":   "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:',.<>?/`~",     # standard printable character
    "?h":   "0123456789AaBbCcDdEeFf",           # hexidecimal
    "?x":   " ",                                # Space character
    "?v":   "aeiou",                            # Vowels
    "?k":   "bcdfghjklmnpqrstvwxyz",            # Consonants
    "?c":   None                                # Custom placeholder
}


# def parse_custom_strings(custom_strings):
#     """
#     Parse the --custom argument into a dictionary.
    
#     Args:
#         custom_strings (str): Custom string input from CLI (e.g., "c=hello").
    
#     Returns:
#         dict: Dictionary mapping custom placeholders to their replacements.
#     """
#     custom_dict = {}
#     if custom_strings:
#         for entry in custom_strings.split(","):
#             key, value = entry.split("=")
#             custom_dict[key] = value
#     return custom_dict


def generate_mask_candidates(mask, custom_strings=None):
    """
    Generates password combinations based on the provided mask and custom strings.
    
    Args:
        mask (str): The mask string specifying the pattern.
        custom_strings (dict): A dictionary of custom placeholders and their replacements.
    
    Yields:
        Encoded password strings based on the mask.
    """

    custom_strings = dict(c=custom_strings) or {}
    char_sets = []

    for m in mask.split("?")[1:]:  # Skip the first empty split
        if f"?{m}" in MASK_MAP and MASK_MAP[f"?{m}"] is not None:
            char_sets.append(MASK_MAP[f"?{m}"])
        elif m in custom_strings:
            char_sets.append(custom_strings[m])  # Use the custom string
        else:
            raise ValueError(f"Invalid or uninitialized mask placeholder: ?{m}")
    print(f"Parsed mask: {mask}")
    print(f"Custom strings: {custom_strings}")
    print(f"Character sets: {char_sets}")
    # Generate combinations
    for combo in itertools.product(*char_sets):
        yield "".join(combo).encode("utf-8")


def yield_maskbased_batches(generator, batch_size):
    batch = []
    total_batches = 0
    for candidate in generator:
        batch.append(candidate)
        if len(batch) >= batch_size:
            total_batches += 1
            yield batch
            batch = []
    if batch:
        total_batches += 1
        yield batch


def get_mask_count(mask, custom_strings=None):
    custom_strings = dict(c=custom_strings) or {}
    char_sets = []

    for m in mask.split("?")[1:]:  # Skip the first empty split
        if f"?{m}" in MASK_MAP and MASK_MAP[f"?{m}"] is not None:
            char_sets.append(MASK_MAP[f"?{m}"])
        elif m in custom_strings:
            char_sets.append(custom_strings[m])  # Use the custom string
        else:
            raise ValueError(f"Invalid or uninitialized mask placeholder: ?{m}")

    # Calculate the total combinations
    return functools.reduce(lambda x, y: x * len(y), char_sets, 1)