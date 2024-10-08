# Passmanager
A CLI password manager for Linux
### ⚠️ Warning ⚠️
While passmanager uses AES-256-CBC encryption, it has not been formally audited for security, as such there may be unknown vulnerabilites. **Use with caution.**
  
# Getting Started
- Clone this repo
- Install passmanager with `install/install.sh` (requires root password)
- Create a config file with `passmanager init`
- Create a password database file with `passmanager new-file <path/to/file.pwdb>` (This file will be the default location for all future password operations)

# Usage
## Password Database (.pwdb) Files:
Passwords are stored in .pwdb files. Every .pwdb is encrypted with a key derived from the user's master password (set at file creation). This can be changed with the password database's key file

## Commands:
### init:
- Usage: `passmanager init`
- Creates a new configuration file in the current user's config directory, must be run before any other commands.
### new-file:
- Usage: `passmanager new-file <PATH>`
- Creates a new password database file at the specified path with no password entries. If there is not currently a default password database file set, this command will set the newly created password database file to the default
- Arguments:
  - `PATH`: The path to create the password file at
### create:
- Usage: `passmanager create <NAME> [-f, --file-path FILE] [-l --length LENGTH] [-n, --note NOTE] [-u, --username USERNAME] [--url URL] [-m --manual (true or false)]`
- Creates a new password with the provided name by default this password is randomly generated.
- Arguments:
  - `NAME`: The name of the password to be created
  - `-f, --file`: The file to store the new password in (if not specified, this will default to the file specified in the user's config file)
  - `-l, --length`: The length, in characters, of the password to be generated (default = 16) 
  - `-n, --note`: An optional note, can be anything
  - `-u, --username`: The username corresponding to the password
  - `--url`: The URL for the site the password's for
  - `-m --manual`: Value must be "true" or "false", if true, this will have the user manually set a password as opposed to generating one randomly
### get:
- Usage: `passmanager get <NAME> [-f, --file-path FILE]`
- Copies the password with the specified name to the user's clipboard
- Arguments:
  - `NAME`: The name of the password to be copied
  - `-f, --file`: The path to the password database file to read the password from
### get-info:
- Usage: Usage: `passmanager get-info <NAME> [-f, --file-path FILE]`
- Displays data (currently, date created and date last modified) about the password with the provided name, without revealing the password itself
- Arguments:
    - `NAME`: The name of the password to be read
    - `-f, --file`: The path to the password database file to read the password from
### delete:
- Usage: `passmanager delete <NAME> [-f, --file-path FILE]`
- Deletes the password with the specified name from the database
- Arguments
  - `NAME`: The name of the password to be deleted
  - `-f, --file`: The file to delete the password in (if not specified, this will default to the file specified in the user's config file)
### update:
- Usage: `passmanager update <NAME> [-f, --file-path FILE] [-n, --note NOTE] [-u, --username USERNAME] [--url URL]`
- Updates the password with the provided name (currently, updates only the password and canno]t update the name)
- Arguments
    - `NAME`: The name of the password to be updated
    - `-n, --note`: Updates the optional note
    - `-u, --username`: Updates the username corresponding to the password
    - `--url`: Updates the URL for the site the password's for
    - `-f, --file`: The file to update the password in (if not specified, this will default to the file specified in the user's config file)
### ls:
- Usage: `passmanager ls [-f, --file-path FILE]`
- Lists the name of every password in the database.
### export-key:
- Usage: `passmanager export-key <KEY-FILE> [-p, --pw-file PW_FILE]`
- Exports the 256-bit key used to decrypt/encrypt the password file. It is of the utmost importance to store key securely, as it is used to reset the file's master password
- Arguments:
  - `KEY-FILE`: The file to store the exported key to.
  - `-p, --pw-file`: The file export the key from (if not specified, this will default to the file specified in the user's config file)
### reset-password
- Usage: `passmanager reset-password <KEY-FILE> [-p, --pw-file PW_FILE]`
- Decrypts the password file with the key in the key file, and prompts the user to set a new master password.
- Arguments:
  - `KEY-FILE`: The file to store the exported key to.
  - `PW_FILE`: The file to reset the master password for (if not specified, this will default to the file specified in the user's config file)
