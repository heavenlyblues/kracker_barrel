import itertools

# Define transformation rules
def apply_rules(word):
    """
    Apply a set of transformation rules to a word.
    Returns a list of transformed words.
    """
    transformations = []

    # Rule 1: Add numbers at the end
    # for num in range(10):
    #     transformations.append(f"{word}{num}")

    # Rule 2: Capitalize the first letter
    transformations.append(word.capitalize())

    # Rule 3: Leetspeak substitution
    leetspeak = word.replace("a", "@").replace("o", "0") # .replace("e", "3").replace("i", "1").replace("s", "$")
    transformations.append(leetspeak)

    # Rule 4: Append special characters -- > @^&
    for char in "!#$%*": 
        transformations.append(f"{word}{char}")

    return transformations

# Combine wordlists and apply rules
def combine_wordlists_with_rules(wordlist1, wordlist2):
    """
    Combine two wordlists and apply transformation rules to each word.
    """
    combined = set()

    # Load wordlists
    with open(wordlist1, "r") as file1, open(wordlist2, "r") as file2:
        words1 = [line.strip() for line in file1]
        words2 = [line.strip() for line in file2]

    # Combine wordlists
    for word1, word2 in itertools.product(words1, words2):
        combined.add(f"{word1}{word2}")  # Simple concatenation
        # combined.add(f"{word1}-{word2}")  # Hyphenated combination

    # Apply rules to combined words
    with open("../refs/combined_with_rules.txt", "w") as output_file:
        for word in combined:
            transformed_words = apply_rules(word)
            for transformed_word in transformed_words:
                output_file.write(transformed_word + "\n")

    print("Combined and transformed wordlist saved to 'combined_with_rules.txt'.")

# Example usage
combine_wordlists_with_rules("../refs/500-worst-passwords.txt", "../refs/500-worst-passwords.txt")