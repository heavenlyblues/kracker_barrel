import argparse

P, G, R, Y, RESET = "\033[0;35m", "\033[92m", "\033[0;31m", "\033[0;33m","\033[0m"
YES, NO = "\U0001F47D", "\U0001F61E"

def display_summary(summary, message, total_count, total_time, password=None):
    """Display a clean summary of the run."""
    if password != None:
        print(f"\n\n{YES} {G}Password match found --> {RESET}{password}")
    else:
        print(f"\n{Y}No match found.{RESET} {NO}")
    print("\n--- Summary ---")
    print(f"{'Workers:':<25}{summary['workers']}")
    print(f"{'Batch size:':<25}{summary['batch_size']}")
    print(f"{'Batches:':<25}{summary['batches']}")
    print(f"{'Items verified:':<25}{total_count}")
    print(f"{'Total items on list:':<25}{summary['items']}")
    print(f"{'Elapsed time:':<25}{total_time:.1f} seconds\n")
    print(f"{P}{message}{RESET}")


def get_command_line_args():
    parser = argparse.ArgumentParser(
        description=f"{P}KRACKER BARREL{RESET}"
    )
    parser.add_argument(
        "input_file", 
        type=str, 
        help="Enter the hashed password file to crack."
    )

    args = parser.parse_args()
    return args