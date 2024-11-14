import argparse
from datetime import datetime
from pathlib import Path


PURPLE, GREEN, RED, YELLOW, RESET = "\033[0;35m", "\033[92m", "\033[0;31m", "\033[0;33m","\033[0m"
YES, NO, STOP = "\U0001F47D", "\U0001F61E", "\U0001F6A8"


def display_summary(
    found_flag, 
    summary_log, 
    cracked_password=None, 
    log_file=f"log_{datetime.now().strftime('%Y%m%d')}.txt"
):
    """Display a clean summary of the run and write to a log file."""
    
    # Define the log directory and file
    log_dir = Path("logs")
    log_dir.mkdir(parents=True, exist_ok=True)  # Create directory if it doesn't exist

    # Prepare log file path
    log_path = (log_dir) / (log_file)
    
    # Open the log file in append mode
    with log_path.open("a", encoding="utf-8") as log:
        
        # Define the width for centering
        width = 49

        # Center the log message
        log_message = f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M.%S')}"
        centered_message = log_message.center(width)
        
        # Write the centered message to the log file
        log.write("-" * 49 + "\n")
        log.write(f"{centered_message}\n")
        log.write("-" * 49 + "\n")
        
        # Build the summary
        if found_flag["found"] == 0:
            result_message = f"Password match found --> {cracked_password}"
            print(f"\n\n{YES} {GREEN}{result_message}{RESET}")
            log.write(f"{result_message}\n")
        elif found_flag["found"] == 1:
            result_message = "No match found."
            print(f"\n{YELLOW}{result_message}{RESET} {NO}")
            log.write(f"{result_message}\n")
        elif found_flag["found"] == 2:
            result_message = "Process interrupted by user."
            print(f"\n{STOP} {RED}{result_message}{RESET}")
            log.write(f"{result_message}\n")
        
        # Write the summary to the log file
        log.write(f"{'File scanned:':<25}{summary_log['file_scanned']}\n")
        log.write(f"{'Workers:':<25}{summary_log['workers']}\n")
        log.write(f"{'Batch size:':<25}{summary_log['batch_size']}\n")
        log.write(f"{'Batches:':<25}{summary_log['batches']}\n")
        log.write(f"{'Items verified:':<25}{summary_log['total_count']}\n")
        log.write(f"{'Items on list:':<25}{summary_log['items']}\n")
        log.write(f"{'Elapsed time:':<25}{summary_log['elapsed_time']:.1f} seconds\n")
        log.write(f"{summary_log['message']}\n")
        log.write("-" * 49 + "\n\n")
    
    # Display the summary on the console
    print("\n" + "-" * 15 + " Summary " + "-" * 15 + "\n")
    print(f"{'File scanned:':<25}{summary_log['file_scanned']}")
    print(f"{'Workers:':<25}{summary_log['workers']}")
    print(f"{'Batch size:':<25}{summary_log['batch_size']}")
    print(f"{'Batches:':<25}{summary_log['batches']}")
    print(f"{'Items verified:':<25}{summary_log['total_count']}")
    print(f"{'Items on list:':<25}{summary_log['items']}")
    print(f"{'Elapsed time:':<25}{summary_log['elapsed_time']:.1f} seconds\n")
    print(f"{PURPLE}{summary_log['message']}{RESET}")


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