# Add Homebrew curl to PATH
export PATH="/opt/homebrew/opt/curl/bin:$PATH"

# Set compiler flags for Homebrew curl
export LDFLAGS="-L/opt/homebrew/opt/curl/lib"
export CPPFLAGS="-I/opt/homebrew/opt/curl/include"
