import itertools


def generate_brute_candidates(settings):
    """
    Generate all possible combinations of characters from the charset
    for lengths ranging from min_length to max_length.
    """
    charset = settings["charset"]
    min_length = settings["min"]
    max_length = settings["max"]
    
    count = 0
    for length in range(min_length, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            count += 1
            yield "".join(combo).encode()
    # print(f"Generated {count} candidates for charset: '{charset}', min_length: {min_length}, max_length: {max_length}")


def yield_brute_batches(generator, batch_size):
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
    # print(f"Total batches generated: {total_batches}")


def get_brute_count(settings):
    """
    Calculate the number of possible passwords generated by brute-force.
    """
    charset = settings["charset"]
    min_length = settings["min"]
    max_length = settings["max"]
    
    total_count = 0
    for length in range(min_length, max_length + 1):
        total_count += len(charset) ** length
    return total_count