from kracker import Cracker
from pathlib import Path
from utils.interface import get_command_line_args

if __name__ == "__main__":
    args = get_command_line_args()
    
    path_to_passwords = Path("refs") / "rockyou.txt" 

    cracker = Cracker(args.input_file, path_to_passwords, batch_size=2000)
    cracker.run()