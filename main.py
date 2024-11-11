from cracker import Cracker
from utils.interface import get_command_line_args

if __name__ == "__main__":
    args = get_command_line_args()
    
    cracker = Cracker(path_to_passwords="refs/dictionary_eng.txt", batch_size=1000)
    cracker.run()