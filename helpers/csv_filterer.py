from tqdm import tqdm
import pandas as pd
from pathlib import Path

def filter_password_csv(input_csv, output_csv, chunksize=100000):
    """
    Filters passwords in the CSV file based on count and length criteria.
    - Removes passwords with a count of 1.
    - Removes passwords shorter than 8 characters.

    Args:
        input_csv (str): Path to the input CSV file.
        output_csv (str): Path to save the filtered CSV file.
        chunksize (int): Number of rows per chunk to process (default: 100,000).
    """

    
    # Open output CSV in write mode to overwrite existing content
    with open(output_csv, "w", encoding="utf-8") as outfile:
        first_chunk = True  # Used to write headers only for the first chunk

        # Get total number of rows for progress bar
        total_rows = sum(1 for _ in open(input_csv, "r", encoding="utf-8")) - 1

        # Read input CSV in chunks
        for chunk in pd.read_csv(input_csv, chunksize=chunksize):
            # Ensure required columns exist
            if "password" not in chunk.columns or "count" not in chunk.columns:
                raise ValueError("The CSV must have 'password' and 'count' columns.")

            # Apply filters
            chunk_filtered = chunk[(chunk["count"] > 1) & (chunk["password"].str.len() >= 8)]

            # Write to output CSV
            chunk_filtered.to_csv(
                outfile,
                mode="a",  # Append mode
                header=first_chunk,  # Write headers only for the first chunk
                index=False
            )
            first_chunk = False  # After the first chunk, disable headers

    print(f"Filtered data saved to {output_csv}")


def remove_numeric_passwords(input_csv, output_csv):
    """
    Removes passwords that contain only numeric characters.

    Args:
        input_csv (str): Path to the input CSV file.
        output_csv (str): Path to save the filtered CSV file.
    """
    # Load the CSV
    df = pd.read_csv(input_csv)

    # Ensure the required column exists
    if "password" not in df.columns:
        raise ValueError("The CSV must have a 'password' column.")

    # Filter out passwords that contain only numbers
    df_filtered = df[~df["password"].str.isnumeric()]

    # Save the filtered data to a new CSV
    df_filtered.to_csv(output_csv, index=False)

    print(f"Filtered data saved to {output_csv}")


def main():

    # Resolve paths relative to the script
    current_dir = Path(__file__).parent
    input_csv = current_dir / "../refs/filtered_passwords.csv"
    output_csv = current_dir / "../refs/filtered_rm_numeric_passwords.csv"

    if not input_csv.exists():
        raise FileNotFoundError(f"Input file not found: {input_csv}")
    if not output_csv.parent.exists():
        raise FileNotFoundError(f"Output directory not found: {output_csv.parent}")
    
    remove_numeric_passwords(input_csv.resolve(), output_csv.resolve())


if __name__ == "__main__":
    main()