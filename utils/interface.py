import argparse

COLOR = "\033[0;35m"
RESET = "\033[0m"

def display_summary(cpu_workers, max_in_flight_futures, batch_size, status_flag, total_count):
    """Display a clean summary of the run."""
    print(f"CPUs used: {cpu_workers}")
    print(f"Max in flight futures: {max_in_flight_futures}")
    print(f"Batch size: {batch_size}")
    print(f"Total passwords attempted: {total_count}")
    print(f"Total time: {status_flag['end'] - status_flag['start']:.1f} seconds")
    print(f"{COLOR}{status_flag['message']}{RESET}")
    status_flag['summary'] = True  # Set flag to avoid duplicate prints


def get_command_line_args():
    parser = argparse.ArgumentParser(
        description=f"{COLOR}KRACKER BARREL{RESET}"
    )
    parser.add_argument(
        "input_file", 
        type=str, 
        help="Enter the hashed password file to crack."
    )

    args = parser.parse_args()
    return args