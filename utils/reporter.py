from datetime import datetime
from pathlib import Path
import sys, time
import logging

# ANSI escape codes for console colors
PURPLE, RED, YELLOW, GREEN = "\033[0;35m", "\033[0;31m", "\033[0;33m", "\033[32m"
LIGHT_YELLOW, BLINK, DIM, RESET = "\033[93m", "\033[5m", "\033[2m", "\033[0m"

# Set up logging
log_dir = Path("logs")
log_dir.mkdir(parents=True, exist_ok=True)  # Ensure logs directory exists
log_file = log_dir / f"log_{datetime.now().strftime('%Y%m%d')}.txt"

logging.basicConfig(
    filename=log_file,
    level=logging.INFO,  # Change to DEBUG for more detailed logs
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Function to create blinking text
def blinking_text(message, duration=3):
    logging.debug(f"Blinking text for {duration} seconds: {message}")
    end_time = time.time() + duration
    while time.time() < end_time:
        sys.stdout.write(f"{BLINK}{LIGHT_YELLOW}{message}{RESET}\r")
        sys.stdout.flush()
        time.sleep(0.5)
        sys.stdout.write(" " * len(message) + "\r")  # Clear the line
        sys.stdout.flush()
        time.sleep(0.5)


# Function to display and log a summary
def display_summary(found_flag, summary_log):
    """Display a clean summary of the run and log details."""

    # Define the width for centering
    width = 57

    # Log the summary header
    log_message = f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M.%S')}"
    centered_message = log_message.center(width)
    logging.info("-" * 57)
    logging.info(centered_message)
    logging.info("-" * 57)

    # Build and log the summary
    if found_flag["found"] > 0:
        for recovered_password in summary_log["pwned"]:
            result_message = f"Password match found --> {recovered_password}"
            logging.info(result_message)

    elif found_flag["found"] == 0:
        result_message = "No match found."
        print(f"\n{YELLOW}{result_message}{RESET}")
        logging.info(result_message)

    elif found_flag["found"] == -1:
        result_message = "Process interrupted by user."
        print(f"\n{RED}{result_message}{RESET}")
        logging.warning(result_message)

    # Log the detailed summary
    logging.info(f"{'Operation:':<25}{summary_log['operation']}")
    logging.info(f"{'Input file:':<25}{summary_log['input_file']}")
    logging.info(f"{'Hash type:':<25}{summary_log['hash_type'].capitalize()}")
    logging.info(f"{'Hash parameters:':<25}{summary_log['hash_parameters']}")
    logging.info(f"{'File scanned:':<25}{summary_log['file_scanned']}")
    logging.info(f"{'Workers:':<25}{summary_log['workers']}")
    logging.info(f"{'Batches:':<25}{summary_log['batches']}")
    logging.info(f"{'Batch size:':<25}{summary_log['batch_size']}")
    logging.info(f"{'Items verified:':<25}{summary_log['total_count']}")
    logging.info(f"{'Items on list:':<25}{summary_log['items']}")
    logging.info(f"{'Elapsed time:':<25}{summary_log['elapsed_time']:.1f} seconds")
    logging.info(f"{summary_log['message']}")
    logging.info("-" * 57 + "\n")

    # Display the summary on the console
    print()
    print("-" * 20 + " Summary " + "-" * 20)
    print(f"{'File scanned:':<25}{summary_log['file_scanned']}")
    print(f"{'Workers:':<25}{summary_log['workers']}")
    print(f"{'Batches:':<25}{summary_log['batches']}")
    print(f"{'Batch size:':<25}{summary_log['batch_size']}")
    print(f"{'Items verified:':<25}{summary_log['total_count']}")
    print(f"{'Items on list:':<25}{summary_log['items']}")
    print(f"{'Elapsed time:':<25}{summary_log['elapsed_time']:.1f} seconds\n")
    print(f"{PURPLE}{summary_log['message']}{RESET}")