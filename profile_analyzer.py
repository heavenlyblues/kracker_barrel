import pstats

# Load the profiling data
stats = pstats.Stats('profile_results.prof')

# Strip directory paths for readability
stats.strip_dirs()

# Sort by cumulative time and print the top 20 functions
stats.sort_stats('cumulative')
stats.print_stats(20)