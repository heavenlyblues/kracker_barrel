from core.kracker import Kracker
from utils.cli import load_args, load_config
import cProfile


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

    # Stop profiling and save results to a file
    profiler.disable()
    profiler.dump_stats('profile_results_1123a.prof')