# ensure the cargo is installed
if !(command -v cargo)
    then echo Please install cargo before running this script!
    exit
fi
# compile the program and move it to the user's bin directory
cargo build -q
sudo cp target/debug/passmanager /usr/bin/passmanager
