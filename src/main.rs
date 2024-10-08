mod passutils;

use std::{fs, io::{self, Error, Write}, str::FromStr};
use clap::{Args, Parser, Subcommand};
use passutils::{export_file_key, export_password_file, find_pw_index, generate_key, generate_password, get_time, import_password_file, key_import_password_file, unwrap_str, PasswordEntry};
use serde_json;
use whoami;
use rpassword;
use copypasta::{self, ClipboardProvider};

const DEFAULT_PREFS: &str= 
"
{
    \"default_file\': \"none\",
    \"default_len\': 16,
    \"allow_upper\": true,
    \"allow_lower\": true,
    \"allow_digit\": true,
    \"allow_special\": true,
}
";

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands
}

#[derive(Subcommand)]
enum Commands{
    Init {},
    NewFile {path: String},
    Create(CreateArgs),
    Get(DefaultArgs),
    GetInfo(DefaultArgs),
    Update(EditArgs),
    Delete(DefaultArgs),
    LS {path: Option<String>},
    ExportKey(KeyArgs),
    ResetPassword(KeyArgs)
}

#[derive(Args)]
struct CreateArgs{
    title: String,
    #[clap(short, long)]
    file_path: Option<String>,
    #[clap(short, long)]
    manual: Option<bool>,
    #[clap(short, long)]
    len: Option<u64>,
    #[clap(short, long)]
    note: Option<String>,
    #[clap(short, long)]
    username: Option<String>,
    #[clap(long)]
    url: Option<String>
}

#[derive(Args)]
struct DefaultArgs{
    title: String,
    #[clap(short, long)]
    file_path: Option<String>
}

#[derive(Args)]
struct EditArgs{
    title: String,
    #[clap(short, long)]
    file_path: Option<String>,
    #[clap(short, long)]
    note: Option<String>,
    #[clap(short, long)]
    username: Option<String>,
    #[clap(long)]
    url: Option<String>
}

// arguments for commands relating to key files (export-key and import-with-key)
#[derive(Args)]
struct KeyArgs{
    key_file: String,
    #[clap(short, long)]
    pw_file: Option<String>
}
// reads a user-provided password without displaying the input
fn read_password(prompt: &str) -> String{
    print!("{}: ", prompt);
    io::stdout().flush().unwrap();
    rpassword::read_password().unwrap()
}

// attempts to log the user in, and updates the file path, and returns the master password
fn login(passwords: &mut Vec<PasswordEntry>, file_path: &mut String, new_path: &Option<String>) -> Result<String, Error>{
    let master_password = read_password("Master Password");
    // load the existing passwords
    if new_path.is_some(){
        *file_path = new_path.clone().unwrap();
    }
    match import_password_file(&file_path, &master_password) {
        Ok(tmp) => {
            *passwords = tmp;
        }
        Err(e) => {
            println!("{}", e);
            return Err(Error::new(std::io::ErrorKind::Other, e.to_string()));
        }
    }
    Ok(master_password)
}

// reads the user's configurtation file and returns the json value of it, or an error, and as a side-effect, updates the file path variable
fn read_user_config() -> Result<(String, u64, bool, bool, bool, bool), Error>{
    // parse the user's config
    let config_path = format!("/home/{}/.config/passmanager/config.json", whoami::username());
    let config_str: String;
    match fs::read_to_string(&config_path){
        Ok(tmp) => {config_str = tmp}
        Err(_) => {
            println!("Failed to read the configuration file.");
            return Err(Error::new(std::io::ErrorKind::Other, ""));
        }
    }
    let config: serde_json::Value;
    match serde_json::from_str(&config_str) {
        Ok(tmp) => {config = tmp}
        Err(_) => {
            println!("Failed to read the configuration file.");
            return Err(Error::new(std::io::ErrorKind::Other, ""));
        }
    }
    // validate that all that all values are present
    let arg_names: [&str; 6] = ["default_file", "default_len", "allow_lower", "allow_upper", "allow_digit", "allow_special"];
    for i in arg_names{
        if config.get(i).is_none(){
            println!("Invalid config file: Missing value for {}", i);
            return Err(Error::new(std::io::ErrorKind::Other, ""));
        }
    }
    // validate that all values are the correct types
    let type_checks = [config["default_file"].is_string(), config["default_len"].is_u64(), config["allow_lower"].is_boolean(), config["allow_upper"].is_boolean(), config["allow_digit"].is_boolean(), config["allow_special"].is_boolean()];
    if type_checks.contains(&false){
        println!("Invalid config file");
        return Err(Error::new(std::io::ErrorKind::Other, ""));
    }
    Ok((config["default_file"].to_string().replace("\"", ""), config["default_len"].as_u64().unwrap(), config["allow_lower"].as_bool().unwrap(), config["allow_upper"].as_bool().unwrap(), config["allow_digit"].as_bool().unwrap(), config["allow_special"].as_bool().unwrap()))
}


fn main() {
    let cli = Cli::parse();
    // run the command
    let mut passwords: Vec<PasswordEntry> = Vec::new();
    match cli.command {
        Commands::Init {  } => {
            // create a configuration file for the user
            if !fs::metadata("/home/{}/.config/passmanager").is_ok(){
                fs::create_dir(format!("/home/{}/.config/passmanager", whoami::username())).unwrap();
            }
            match fs::write(format!("/home/{}/.config/passmanager/config.json", whoami::username()), DEFAULT_PREFS)
            {
                Ok(_) => {println!("Welcome to passmanager!")}
                Err(_) => {println!("Could not initialize the config file")}
            }
             
        }
        Commands::NewFile{path} => {
            let config: (String, u64, bool, bool, bool, bool);
            match read_user_config() {
                Ok(tmp) => {config = tmp}
                Err(_) => {return;}   
            }
            // check if the file already exists
            if fs::metadata(&path).is_ok() {
                println!("A password database file at that path already exists!");
                return;
            }
            let password = read_password("Password");
            let confirm = read_password("Confirm Password");
            if password != confirm{
                println!("Password does not match confirmation. Exiting...");
                return;
            }
            // create the password file, and make it the default file if there is not one already
            export_password_file(&path, password, passwords).expect("Cannot create the password file");
            if config.0 == "none"{
                // update the config file with a new default file
                let config_path = format!("/home/{}/.config/passmanager/config.json", whoami::username());
                let config_str = fs::read_to_string(&config_path).unwrap();
                let new_config = serde_json::Value::from_str(&config_str).unwrap();
                fs::write(config_path, new_config.to_string()).unwrap();

            }
            println!("New password file created!");
        }
        // creates a new password
        Commands::Create(args) => {
            // parse the user config
            let config: (String, u64, bool, bool, bool, bool);
            match read_user_config() {
                Ok(tmp) => {config = tmp}
                Err(_) => {return;}   
            }
            let mut file_path = config.0;
            // log the user in
            let master_password: String;
            match login(&mut passwords, &mut file_path, &args.file_path){
                Ok(tmp) => {master_password = tmp}
                Err(_) => {return;}
            }
            // validate the password metadata
            if args.title.contains('~'){
                println!("Passwords cannot contain a tilde (~)");
                return;
            }
            for i in [&args.note, &args.username, &args.url]{
                if unwrap_str(i, "").contains("~"){
                    println!("Pasword information cannot contain a tilde (~)");
                    return;
                }
            }
            if find_pw_index(&passwords, &args.title).is_some(){
                println!("A password with the name {} already exists", args.title);
                return;
            }
            // initialize the password and key
            let mut password: String = String::new();
            let manual: bool;
            if args.manual.is_none(){manual = false;}
            else{manual=args.manual.unwrap();}
            match manual{
                true => {
                    password = read_password(format!("Password for {}", args.title).as_str());
                    let confirm = read_password("Confirm");
                    if confirm != password{
                        println!("Password does not match confirmation");
                        return;
                    }
                }
                false => {
                    // read the user preferences to generate a password, and create the password
                    let mut pw_len = config.1;
                    if args.len.is_some(){
                        pw_len = args.len.unwrap();
                    }
                    generate_password(pw_len, config.2, config.3, config.4, config.5, &mut password);
                }
            }
            let mut pw_key: [u8; 32] = [0; 32];
            generate_key(&mut pw_key);
            let time = get_time();
            passwords.push(PasswordEntry::new(&pw_key, &args.title, &password, &time, &time, &args.note, &args.username, &args.url));
            // update the passwords
            export_password_file(&file_path, master_password, passwords).expect("Cannot create the new password");
            println!("Password created succesfully")
        }
        Commands::Get(args) => {
            // parse the user config
            let config: (String, u64, bool, bool, bool, bool);
            match read_user_config() {
                Ok(tmp) => {config = tmp}
                Err(_) => {return;}   
            }
            let mut file_path = config.0;
            // log the user in
            if login(&mut passwords, &mut file_path, &args.file_path).is_err(){
                return;
            }
            // copy the password to the user's clipboard
            match find_pw_index(&passwords, &args.title){
                Some(index) => {
                    let mut ctx = copypasta::ClipboardContext::new().unwrap();
                    ctx.set_contents(passwords[index].password.clone()).unwrap();
                    println!("Password copied to clipboard\nExit the program with Ctrl+C after you've pasted the password");
                    loop {}
                }
                None => {println!("The password for {} does not exist", &args.title)}
            }
        }
        Commands::GetInfo(args) => {
            // parse the user config
            let config: (String, u64, bool, bool, bool, bool);
            match read_user_config() {
                Ok(tmp) => {config = tmp}
                Err(_) => {return;}   
            }
            let mut file_path = config.0;
            // log the user in
            if login(&mut passwords, &mut file_path, &args.file_path).is_err(){
                return;
            }
            match find_pw_index(&passwords, &args.title){
                Some(index) => {
                    let tmp_pw = &passwords[index];
                    println!("Site name: {}\nDate created: {}\nLast modified: {}", tmp_pw.site_name, tmp_pw.create_date, tmp_pw.modify_date);
                    // print all optional values, if present
                    if tmp_pw.note != "" {
                        println!("Note: {}", tmp_pw.note)
                    }
                    if tmp_pw.username != "" {
                        println!("Username: {}", tmp_pw.username)
                    }
                    if tmp_pw.url != "" {
                        println!("URL: {}", tmp_pw.url)
                    }
                }
                None => {println!("The password for {} does not exist", args.title);}
            }
        }
        Commands::Delete(args) => {
            // parse the user config
            let config: (String, u64, bool, bool, bool, bool);
            match read_user_config() {
                Ok(tmp) => {config = tmp}
                Err(_) => {return;}   
            }
            let mut file_path = config.0;
            // log the user in
            let master_password: String;
            match login(&mut passwords, &mut file_path, &args.file_path){
                Ok(tmp) => {master_password = tmp}
                Err(_) => {return;}
            }
            match find_pw_index(&passwords, &args.title){
                Some(index) => {
                    passwords.remove(index);
                    export_password_file(&file_path, master_password, passwords).unwrap();
                    println!("Password deleted successfully");
                }
                None => {println!("The password for {} does not exist", &args.title);}
            }

        }
        Commands::Update(args) => {
            // parse the user config
            let config: (String, u64, bool, bool, bool, bool);
            match read_user_config() {
                Ok(tmp) => {config = tmp}
                Err(_) => {return;}   
            }
            let mut file_path = config.0;
            // log the user in
            let master_password: String;
            match login(&mut passwords, &mut file_path, &args.file_path){
                Ok(tmp) => {master_password = tmp}
                Err(_) => {return;}
            }
            match find_pw_index(&passwords, &args.title){
                Some(index) => {
                    let tmp = &passwords[index];
                    // get the new password
                    let mut new_pass = read_password("New password (leave blank to generate a random password)");
                    if new_pass == ""{
                        let pw_len = config.1;
                        generate_password(pw_len, config.2, config.3, config.4, config.5, &mut new_pass);
                    }
                    else if new_pass.contains("~"){
                        println!("Passwords cannot contain a tilde (~)");
                        return;
                    }
                    // determine if new options have been set
                    let note = unwrap_str(&args.note, tmp.note.as_str());
                    let uname = unwrap_str(&args.username, tmp.username.as_str());
                    let url = unwrap_str(&args.url, tmp.url.as_str());
                    // validate the above
                    for i in [&note, &uname, &url]{
                        if i.contains("~"){
                            println!("Password information cannot have tildes (~)");
                            return;
                        }
                    }
                    // update the password entry
                    let pass_entry = PasswordEntry::new(&tmp.key, &tmp.site_name, &new_pass, &tmp.create_date, &get_time(), &Some(note), &Some(uname), &Some(url));
                    passwords[index] = pass_entry;
                    export_password_file(&file_path, master_password, passwords).unwrap();
                    println!("Password updated successfully");
                }
                None => {println!("The password for {} does not exist", &args.title);}
            }
        }
        Commands::LS { path } => {
            // parse the user config
            let config: (String, u64, bool, bool, bool, bool);
            match read_user_config() {
                Ok(tmp) => {config = tmp}
                Err(_) => {return;}   
            }
            let mut file_path = config.0;
            // log the user in
            match login(&mut passwords, &mut file_path, &path){
                Ok(_) => {}
                Err(_) => {return;}
            }
            if passwords.len() > 0{
                println!("Existing passwords:");
                for i in passwords{
                    println!("\t{}", &i.site_name)
                }
            }
            else{println!("No passwords are in this database.")}
        }
        Commands::ExportKey(args) => {
            // parse the user config and the desired file path
            let config: (String, u64, bool, bool, bool, bool);
            match read_user_config() {
                Ok(tmp) => {config = tmp}
                Err(_) => {return;}   
            }
            let mut pw_file_path = config.0;
            if args.pw_file.is_some(){
                pw_file_path = args.pw_file.unwrap();
            }
            // attempt to export the key to the chosen file
            let master_password = read_password("Master Password");
            match export_file_key(&pw_file_path, &master_password) {
                Ok(key) => {
                    if fs::write(&args.key_file, key).is_ok(){
                        println!("Key exported succesfully.");
                        return;
                    }
                    println!("Cannot write the key to the keyfile")
                }
                Err(e) => {println!("{}", e)}
            }
        }
        Commands::ResetPassword(args) => {
            // parse the user config and the desired file path
            let config: (String, u64, bool, bool, bool, bool);
            match read_user_config() {
                Ok(tmp) => {config = tmp}
                Err(_) => {return;}   
            }
            let mut pw_file_path = config.0;
            if args.pw_file.is_some(){
                pw_file_path = args.pw_file.unwrap();
            }
            // get the new password for the password file
            let new_password = read_password("New password");
            let confirm = read_password("Confirm");
            if new_password != confirm{
                println!("New password does not match confirmation");
                return;
            }
            // attempt to decrypt the current password file
            let passwords: Vec<PasswordEntry>;
            match key_import_password_file(&pw_file_path, &args.key_file){
                Ok(tmp) => {passwords = tmp}
                Err(e) => {
                    println!("{}", e);
                    return;
                }
            }
            // overwrite the password file with new password
            export_password_file(&pw_file_path, new_password, passwords).expect("Cannot update the password file");
            println!("Password updated successfully");
        }
   }
}   
