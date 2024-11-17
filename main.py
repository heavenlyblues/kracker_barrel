from modules.kracker import Kracker
from utils.cli import load_args, load_config


if __name__ == "__main__":
    # Load configuration from YAML file
    config = load_config() # <-- Add custom config if desired

    # Parse arguments, with config as defaults
    args = load_args(config)

    # Pass parsed arguments to Kracker
    cracker = Kracker(args)

    # Run the cracking process
    cracker.run()
