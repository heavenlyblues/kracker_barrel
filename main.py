from kracker import Kracker
from utils.cli import get_command_line_args


if __name__ == "__main__":
    args = get_command_line_args()

    cracker = Kracker(args)

    cracker.run()
