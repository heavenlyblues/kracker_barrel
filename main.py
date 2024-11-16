from kracker import Kracker
from pathlib import Path
from utils.interface import get_command_line_args

if __name__ == "__main__":
    args = get_command_line_args()
    
    path_to_passwords = Path("refs") / "dictionary_eng.txt" 

    cracker = Kracker(args.input_file, path_to_passwords, batch_size=5000)

    cracker.run()