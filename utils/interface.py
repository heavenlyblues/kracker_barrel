import argparse

PURPLE, GREEN, RED, YELLOW, RESET = "\033[0;35m", "\033[92m", "\033[0;31m", "\033[0;33m","\033[0m"
YES, NO, STOP = "\U0001F47D", "\U0001F61E", "\U0001F6A8"

def display_exit_summary(found_flag, exit_summary, exit_message, total_count, total_time, cracked_password=None):
    """Display a clean summary of the run."""
    if found_flag["found"] == 0:
        print(f"\n\n{YES} {GREEN}Password match found --> {RESET}{cracked_password}")
    elif found_flag["found"] == 1:
        print(f"\n{YELLOW}No match found.{RESET} {NO}")
    elif found_flag["found"] == 2:
        print(f"\n{STOP} {RED}Process interrupted by user.{RESET}")
    print("\n--- Summary ---")
    print(f"{'Workers:':<25}{exit_summary['workers']}")
    print(f"{'Batch size:':<25}{exit_summary['batch_size']}")
    print(f"{'Batches:':<25}{exit_summary['batches']}")
    print(f"{'Items verified:':<25}{total_count}")
    print(f"{'Total items on list:':<25}{exit_summary['items']}")
    print(f"{'Elapsed time:':<25}{total_time:.1f} seconds\n")
    print(f"{PURPLE}{exit_message}{RESET}")


def get_command_line_args():
    parser = argparse.ArgumentParser(
        description=f"{PURPLE}KRACKER BARREL{RESET}"
    )
    parser.add_argument(
        "input_file", 
        type=str, 
        help="Enter the hashed password file to crack."
    )

    args = parser.parse_args()
    return args