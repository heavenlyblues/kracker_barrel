import sys
import time
import logging


LIGHT_YELLOW, BLINK, RESET = "\033[93m", "\033[5m", "\033[0m"


# Function to create blinking text -- not currently in use
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