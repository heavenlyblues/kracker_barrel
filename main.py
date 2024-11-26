from core.kracker import Kracker
from utils.cli import load_args, load_config
import datetime
import cProfile
from pathlib import Path


if __name__ == "__main__":
    # Profile the execution of your program and save results
    profiler = cProfile.Profile()
    profiler.enable()

    # Load configuration from YAML file
    config = load_config() # <-- Add custom config if desired

    # Parse arguments, with config as defaults
    args = load_args(config)

    # Pass parsed arguments to Kracker
    cracker = Kracker(args)

    # Run the cracking process
    cracker.run()

    # Create profiling file with time stame
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    profiling_dir = Path("profiling")
    profiling_dir.mkdir(exist_ok=True)
    filename = profiling_dir / f"profile_results_{timestamp}.prof"
    profiler.disable()
    profiler.dump_stats(filename)