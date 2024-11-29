from core.kracker import Kracker, BatchManager, Workers
from utils.reporter import Reporter
from utils.cli import load_args, load_config
import datetime
import cProfile
from pathlib import Path


if __name__ == "__main__":
    # Profile the execution of your program and save results
    profiler = cProfile.Profile()
    profiler.enable()

    # Load configuration from YAML file
    args = load_args(load_config()) # <-- Add custom config if desired
    kracker = Kracker(args)
    batch_man = BatchManager(kracker)
    reporter = Reporter(kracker)
    workers = Workers(kracker, batch_man, reporter)

    workers.run()

    # Create profiling file with time stame
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    profiling_dir = Path("profiling")
    profiling_dir.mkdir(exist_ok=True)
    filename = profiling_dir / f"profile_results_{timestamp}.prof"
    profiler.disable()
    profiler.dump_stats(filename)