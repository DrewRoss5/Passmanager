# Passmanager
A CLI password manager written in Rust
### ⚠️ Warning ⚠️
While passmanager uses AES-256-CBC encryption, it has not been formally audited for security, as such there may be unknown vulnerabilites. **Use with caution.**

# Roadmap/ToDo
- Add export functionality
- Add support for bulk actions
- Add password "directories" to store related passwords
- Add additional password metadata (URL, Last Modified, Creation Date, etc.)
- 
# Getting Started
- Clone this repo
- Install passmanager with `install/install.sh` (requires root password)
- Create a config file with `passmanager init`
- Create a password database file with `passmanager new-file <path/to/file.pwdb>` (This file will be the default location for all future password operations)

# Usage
## Password Database (.pwdb) Files:
Passwords are stored in .pwdb files. Every .pwdb is encrypted with a key derived from the user's master password (set at file creation). Take extreme care to remember/store this master password, because there is currently no way to recover password data without it. 

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
- Usage: `passmanager create <NAME> \[-f, --file FILE] \[-l --length LENGTH] \[-m --manual (true or false)]`
- Creates a new password with the provided name by default this password is randomly generated.
- Arguments
  - `NAME`: The name of the password to be created
  - `-f, --file`: The file to store the new password in (if not specified, this will default to the file specified in the user's config file)
  - `-l, --length`: The length, in characters, of the password to be generated (default = 16)
  - `-m --manual`: Value must be "true" or "false", if true, this will have the user manually set a password as opposed to generating one randomly
### delete:
- Usage: `passmanager delete <NAME> \[-f, --file FILE]`
- Deletes the password with the specified name from the database
- Arguments
  - `NAME`: The name of the password to be deleted
  - `-f, --file`: The file to delete the password in (if not specified, this will default to the file specified in the user's config file)
### update:
- Usage: `passmanager update <NAME> \[-f, --file FILE]`
- Updates the password with the provided name (currently, updates only the password and cannot update the name)
- Arguments
    - `NAME`: The name of the password to be updated
    - `-f, --file`: The file to update the password in (if not specified, this will default to the file specified in the user's config file)
### ls:
- Usage: `passmanager ls`
- Lists the name of every password in the database.

