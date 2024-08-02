mod passutils;

use std::{fs, io::{self, Error, Write}};
use clap::{Args, Parser, Subcommand};
use passutils::{export_password_file, find_pw_index, generate_key, generate_password, import_password_file, PasswordEntry};
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
    command: Commands,
}

#[derive(Subcommand)]
enum Commands{
    Init {},
    NewFile {path: String},
    Create(CreateArgs),
    Get(DefaultArgs),
    Update(DefaultArgs),
    Delete(DefaultArgs),
    LS {path: Option<String>}
}

#[derive(Args)]
struct CreateArgs{
    title: String,
    #[clap(short, long)]
    file_path: Option<String>,
    #[clap(short, long)]
    manual: Option<bool>,
    #[clap(short, long)]
    len: Option<u64>
}

#[derive(Args)]
struct DefaultArgs{
    title: String,
    #[clap(short, long)]
    file_path: Option<String>
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
fn read_user_config(file_path: &mut String) -> Result<serde_json::Value, Error>{
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
    *file_path = config.get("default_file").unwrap().to_string().replace("\"", "");
    Ok(config)
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
            let mut file_path = String::new();
            let mut config: serde_json::Value;
            match read_user_config(&mut file_path) {
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
            if config["default_file"] == "none"{
                config["default_file"] = serde_json::Value::String(path);
                fs::write(format!("/home/{}/.config/passmanager/config.json", whoami::username()), config.to_string()).expect("Cannot update the config file");

            }
            println!("New password file created!");
        }
        // creates a new password
        Commands::Create(args) => {
            // parse the user config
            let mut file_path = String::new();
            let config: serde_json::Value;
            match read_user_config(&mut file_path) {
                Ok(tmp) => {config = tmp}
                Err(_) => {return;}   
            }
            // log the user in
            let master_password: String;
            match login(&mut passwords, &mut file_path, &args.file_path){
                Ok(tmp) => {master_password = tmp}
                Err(_) => {return;}
            }
            // validate the password name
            if args.title.contains('~'){
                println!("Passwords cannot contain a tilde (~)");
                return;
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
                    let mut pw_len = config["default_len"].as_u64().unwrap();
                    if args.len.is_some(){
                        pw_len = args.len.unwrap();
                    }
                    generate_password(pw_len, 
                                        config["allow_lower"].as_bool().unwrap(), 
                                        config["allow_upper"].as_bool().unwrap(),
                                         config["allow_digit"].as_bool().unwrap(), 
                                        config["allow_special"].as_bool().unwrap(), 
                                        &mut password);
                }
            }
            let mut pw_key: [u8; 32] = [0; 32];
            generate_key(&mut pw_key);
            passwords.push(PasswordEntry::new(&pw_key, &args.title, &password));
            // update the passwords
            export_password_file(&file_path, master_password, passwords).expect("Cannot create the new password");
            println!("Password created succesfully")
        }
        Commands::Get(args) => {
            // parse the user config
            let mut file_path = String::new();
            let config: serde_json::Value;
            match read_user_config(&mut file_path) {
                Ok(tmp) => {config = tmp}
                Err(_) => {return;}   
            }
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
        Commands::Delete(args) => {
            // parse the user config
            let mut file_path = String::new();
            let config: serde_json::Value;
            match read_user_config(&mut file_path) {
                Ok(tmp) => {config = tmp}
                Err(_) => {return;}   
            }
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
            let mut file_path = String::new();
            let config: serde_json::Value;
            match read_user_config(&mut file_path) {
                Ok(tmp) => {config = tmp}
                Err(_) => {return;}   
            }
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
                        let pw_len = config["default_len"].as_u64().unwrap();
                        generate_password(pw_len, 
                            config["allow_lower"].as_bool().unwrap(), 
                            config["allow_upper"].as_bool().unwrap(),
                             config["allow_digits"].as_bool().unwrap(), 
                            config["allow_special"].as_bool().unwrap(), 
                            &mut new_pass);
                    }
                    // update the password entry
                    let pass_entry = PasswordEntry::new(&tmp.key, &tmp.site_name, &new_pass);
                    passwords[index] = pass_entry;
                    export_password_file(&file_path, master_password, passwords).unwrap();
                    println!("Password updated successfully");
                }
                None => {println!("The password for {} does not exist", &args.title);}
            }
        }
        Commands::LS { path } => {
            // parse the user config
            let mut file_path = String::new();
            let config: serde_json::Value;
            match read_user_config(&mut file_path) {
                Ok(tmp) => {config = tmp}
                Err(_) => {return;}   
            }
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
        
   }
}   