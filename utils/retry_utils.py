import time
import sys
import logging

class CustomHashingError(Exception):
    """Custom exception for critical hashing errors."""
    pass

def run_with_retries(target_function, max_retries=3, delay=5, *args, **kwargs):
    """Runs a target function with retry logic for handling critical errors.

    Parameters:
        target_function (function): The function to execute with retries.
        max_retries (int): The maximum number of retries.
        delay (int): The delay (in seconds) between retries.
        *args, **kwargs: Arguments and keyword arguments to pass to the target function.

    Raises:
        CustomHashingError: If a critical error persists after max_retries.
    """
    retry_count = 0

    while retry_count < max_retries:
        try:
            # Attempt to run the target function
            return target_function(*args, **kwargs)  # Run and return if successful

        except CustomHashingError as e:
            # Log critical error
            retry_count += 1
            logging.error(f"Critical error encountered: {e}. Attempt {retry_count}/{max_retries}")
            
            if retry_count >= max_retries:
                logging.critical("Max retries reached. Terminating program.")
                sys.exit(1)  # Exit with error code
            else:
                logging.warning(f"Retrying in {delay} seconds after critical error...")
                time.sleep(delay)  # Wait before retrying

        except Exception as e:
            # Handle any other unexpected exceptions
            logging.error(f"Unexpected error: {e}. Terminating program.")
            sys.exit(1)