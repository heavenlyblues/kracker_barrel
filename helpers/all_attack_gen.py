# Expand Dictionary Attack
# Description: Combine multiple wordlists (e.g., rockyou.txt, 
# dictionary.txt) for a more comprehensive attack.
def merge_wordlists(output_file, *input_files):
    seen = set()
    with open(output_file, "w") as outfile:
        for infile in input_files:
            with open(infile, "r") as f:
                for line in f:
                    word = line.strip()
                    if word not in seen:
                        outfile.write(word + "\n")
                        seen.add(word)

"""merge_wordlists("merged_wordlist.txt", "rockyou.txt", "dictionary.txt")"""

# Hybrid attack
# Description: Append or prepend numbers, symbols, or years to dictionary words.
def hybrid_attack(wordlist, append_list=None, prepend_list=None):
    append_list = append_list or ["123", "!", "2023"]
    prepend_list = prepend_list or ["123", "!", "2023"]

    for word in wordlist:
        yield word  # Original word
        for append in append_list:
            yield word + append
        for prepend in prepend_list:
            yield prepend + word

"""wordlist = ["password", "admin", "welcome"]
for variation in hybrid_attack(wordlist):
    print(variation)"""


# Rule-based attack
# Description: Apply simple transformations to dictionary words, such as:
# Capitalization: password → Password.
# Leetspeak: password → p@ssw0rd.
# Reversal: password → drowssap.

def apply_rules(word):
    yield word  # Original word
    yield word.capitalize()  # Capitalized
    yield word[::-1]  # Reversed
    yield word.replace("a", "@").replace("o", "0").replace("s", "$")  # Leetspeak

"""for variation in apply_rules("password"):
    print(variation)"""


# Mask-based attack
# Description: Test passwords that follow common patterns:
# ?l?l?l?d → Four lowercase letters followed by a digit.
# ?u?u?d?d?s → Two uppercase letters, two digits, and a symbol.
from itertools import product

def generate_from_mask(mask):
    mask_map = {
        "?l": "abcdefghijklmnopqrstuvwxyz",
        "?u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "?d": "0123456789",
        "?s": "!@#$%^&*()",
    }
    charset = [mask_map.get(char, char) for char in mask]
    for combination in product(*charset):
        yield "".join(combination)

"""for password in generate_from_mask("?l?l?l?d"):
    print(password)"""

# Wordlist Combination Attack
# Description: Combine words from two lists into a single password.

from itertools import product

def combine_wordlists(wordlist1, wordlist2, separator=""):
    for word1, word2 in product(wordlist1, wordlist2):
        yield f"{word1}{separator}{word2}"

"""list1 = ["happy", "blue"]
list2 = ["dog", "sky"]
for password in combine_wordlists(list1, list2):
    print(password)"""

# Optimize Brute-Force Attack
# Description: Focus brute-force efforts on smaller, more likely character sets.
from itertools import product

def brute_force_attack(charset, min_length=1, max_length=5):
    for length in range(min_length, max_length + 1):
        for attempt in product(charset, repeat=length):
            yield "".join(attempt)

"""for password in brute_force_attack("abc123", min_length=2, max_length=3):
    print(password)"""