extern crate bcrypt;
extern crate aes;
extern crate block_modes;
extern crate sha2;
extern crate csv;

use aes::Aes256;
use block_modes::{BlockMode, Cbc, block_padding::Pkcs7};
use sha2::{Digest, Sha256};
use std::env;
use openssl::rand::rand_bytes;
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

//cryptography crate
use bcrypt::{hash, verify, DEFAULT_COST};

//input and output library
use std::io;
use std::fs::File;

//data structure for passwords
struct SessionPassword {

    /* 

    where_from refers to where is the password from?

        ex. firefox, spotify
    
    password refers to the unhashed password.

    password will only be available after providing a correct user password
    
    */

    where_from : String,
    password : String,
}

//allows me to implement {:?} with SessionPassword
impl std::fmt::Debug for SessionPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionPassword")
            .field("where_from", &self.where_from)
            .field("password", &"*************") // Mask the password for security reasons
            .finish()
    }
}


                                                                                /* MAIN FUNCTION  */

fn main() {
    
    //vector for passwords
    let mut passwords_vector : Vec<SessionPassword> = Vec::new();

    //vector for keys TEMPORAL
    let mut key_vector : Vec<String> = Vec::new();

    clear_screen();
    loop {

    println!(r" ______                                           __                                
|   __ \.---.-.-----.-----.--.--.--.-----.----.--|  |                               
|    __/|  _  |__ --|__ --|  |  |  |  _  |   _|  _  |                               
|___|   |___._|_____|_____|________|_____|__| |_____|                               
                                                                                    
 _______                                                 ____      ______    ______ 
|   |   |.---.-.-----.---.-.-----.-----.----.    .--.--.|_   |    |      |  |      |
|       ||  _  |     |  _  |  _  |  -__|   _|    |  |  | _|  |_ __|  --  |__|  --  |
|__|_|__||___._|__|__|___._|___  |_____|__|       \___/ |______|__|______|__|______|
                           |_____|                                                  ");


    println!("\n\n\nThis is a simple password manager program which lets users securely store, manage, 
and retrieve passwords. This project uses the bcrypt library to hash and validate passwords, 
ensuring that user data is secure.\n\n");
    
    //main menu
    println!("1. Hash new password\n2. Reveal Password\n3. Exit\n");

    let mut menu_choice : u8;
 
    loop {
        //String for user input
        let mut user_input = String::new();

        io::stdin().read_line(&mut user_input).expect("(-) Failed to read line");

        /* 
            
        pub fn trim(&self) -> &str

        Returns a string slice with leading and trailing whitespace removed.

        ‘Whitespace’ is defined according to the terms of the Unicode Derived Core Property White_Space, which includes newlines.
        
        */

        menu_choice = match user_input.trim().parse() { Ok(n) => n, Err(_) => { println!("(-) Not a valid number"); continue;} };

        if menu_choice < 1 || menu_choice > 3 {
            println!("Number outside of bounds..... try again\n");
        } else {
            break;
        }
    }

    
        if menu_choice == 1 {
            //go to fn
            hash_new_password(&mut passwords_vector, &mut key_vector);
            clear_screen();
        } else if menu_choice == 2  {
            //reveal passwords
            clear_screen();
            show_password_vector(&passwords_vector, &key_vector);
        } else {
            println!("Exiting....\n");
            return;
        }
    }
}

                                                                            /* HASH NEW PASSWORD MENU  */



//Function to create user and encrypt rewuired number of passwords
fn hash_new_password(store: &mut Vec<SessionPassword>, keychain: &mut Vec<String>){

    clear_screen();
    println!("\t\t+=============================================+");
    println!("\t\t+               Hashing Passwords             +");
    println!("\t\t+=============================================+\n\n\n");

    println!("\nYou will have to create a username and give a password for further reading and creating password.\n");

    println!("\n\n\n\n\n");
    
    //creates csv file for user passwords
    let user_file = File::create("user_csv.csv").expect("(-) Failes at csv creation");
    let mut writer = csv::Writer::from_writer(user_file);

    //write headers for csv file
    writer.write_record(&["where_from","password"]).expect("(-) Failed at writing to csv file");
    
    //Creates a master user and hashed password for further authentication
    {
        println!("\nPlease input a username: ");
        //create a buffer for username
        let mut buffer = String::new();
        io::stdin().read_line(&mut buffer).expect("(-) Failed at reading stdin");
        
        let username = buffer.trim().to_string();

        println!("\nPlease input a password: ");

        let mut pass_buffer = String::new();
        io::stdin().read_line(&mut pass_buffer).expect("(-) Failed at reading stdin");

        let new_password = pass_buffer.trim().to_string();

        let hashed_user = hash(new_password, DEFAULT_COST).expect("(-) Failed at user password hash");
        
        //struct instance
        let new_user_password = SessionPassword { where_from: username, password: hashed_user, };
        
        store.push(new_user_password);
        writer.write_record(&[store[0].where_from.as_str(), store[0].password.as_str()]).expect("(-) Failed at vec writing csv");

        //initiate keychain w 0 value
        keychain.push("000".to_string());
    }

    //stores given number of passwords in a vec<SessionPasswords> SEE STRUCT
    println!("\nNow please enter how many passwords you wish to create (MAX 255): ");

    {
        //store # of passwords user wishes to create
        let passwords_to_create : u8;

        //buffer for stdin
        let mut buffer = String::new();
        io::stdin().read_line(&mut buffer).expect("(-) Failed at reading stdin");


        // menu_choice = match user_input.trim().parse() { Ok(n) => n, Err(_) => { println!("(-) Not a valid number"); continue;} };
        //parse stidn 
        passwords_to_create = match buffer.trim().parse() { Ok(n) => n, Err(_) => {println!("(-) Not a valid number"); return;} };
        

        //create passwords_to_create num of passwords, from 1 to n
        for _i in 1..=passwords_to_create {

            println!("\nUsername/Url: ");
            //create a buffer for username
            let mut buffer = String::new();
            io::stdin().read_line(&mut buffer).expect("(-) Failed at reading stdin");
            
            let username = buffer.trim().to_string();

            println!("\nPlease input a password: ");

            let mut pass_buffer = String::new();
            io::stdin().read_line(&mut pass_buffer).expect("(-) Failed at reading stdin");
                    
            //creates a key using rand_chars()
            let key_string : String = rand_chars();
            let key = Sha256::digest(key_string.as_bytes());

            let new_password = pass_buffer.trim().to_string();

            //let hashed_new_password = hash(new_password, DEFAULT_COST).expect("(-) Failed at hash of new password");
            let encrypted_password = encrypt_text(&key, &new_password);
            
            //fills struct instance with user given values (stdin())
            let new_user_password = SessionPassword { where_from: username, password: encrypted_password, };
            
            //pushes value to vec<>
            store.push(new_user_password);

            keychain.push(key_string);
        }
        
        //itterates over vec and writes the records to the csv file created ABOVE
        for storage in store {
            writer.write_record(&[storage.where_from.clone(), storage.password.clone()]).expect("(-) Failed vec parsing to csv");
        }
    }
}




                                                                            /* REVEAL PASSWORD MENU  */

//asks for password, generates key and calls encrypt fn
fn encrypt_new_password(){



}

//retrieves key and hex string to decrypt, calls decrypt fn
fn decrypt_new_password(pass_vec: &Vec<SessionPassword>, keychain: &Vec<String>) {
    // Ask for user master password
    println!("Please input your master password for {}: ", pass_vec[0].where_from);

    let hash: &str = &pass_vec[0].password;

    loop {
        let mut buffer = String::new();
        io::stdin().read_line(&mut buffer).expect("(-) Failed to read master password");

        if buffer.trim() == "n" { return; }

        let verify_result = verify(buffer.trim(), &hash).expect("(-) Failed to verify master password");

        if verify_result {
            println!("\nCorrect admin password\n");
            println!("Which password do you want to reveal?\n");
            print_saved_passwords(pass_vec);

            let mut menu_choice = String::new();
            io::stdin().read_line(&mut menu_choice).expect("(-) Failed to read input");
            let menu_choice: u8 = match menu_choice.trim().parse() {
                Ok(n) => n,
                Err(_) => { println!("(-) Not a valid number"); return; }
            };

            if menu_choice == 1 { 
                println!("Cannot reveal master password...\n"); 
                return; 
            }

            if menu_choice < 1 || menu_choice > (pass_vec.len() as u8) { 
                println!("(-) Number outside of bounds"); 
                return; 
            }

            let key = Sha256::digest((keychain[(menu_choice - 1) as usize]).as_bytes());
            let decrypted_password = &pass_vec[(menu_choice - 1) as usize].password;
            
            //match decrypted text and print both decrypted and where_from addr
            match decrypt_text(&key, &decrypted_password) {
                Ok(decrypted_text) => {
                    
                    println!("\t\t+=============================================+");
                    println!("\t\t+              Revealed Password              +");
                    println!("\t\t+=============================================+\n\n\n");

                    println!("+=======================================================+");
                    println!("+{}: {} +", pass_vec[(menu_choice - 1) as usize].where_from, decrypted_text);
                    println!("+=======================================================+\n");
                },
                Err(e) => {
                    println!("Decryption failed: {}", e);
                }
            }
            break;
        } else { 
            println!("Incorrect master password, try again or press 'n' to quit.\n"); 
        }
    }
}


//Shows created/read vector and its corresponding username and where_from
fn show_password_vector(/*key: &[u8],*/ vector: &Vec<SessionPassword>, keychain: &Vec<String>){
        
    print_saved_passwords(vector);

    {
        println!("1. Reveal password\n2. Delete password\n3. Exit");
        let mut buffer = String::new();
        io::stdin().read_line(&mut buffer).expect("(-) Failed at readig stdin");

        let menu_choice : u8; 
        menu_choice = match buffer.trim().parse() { Ok(n) => n, Err(_) => {println!("(-) Not a valid number"); return;} };

        if menu_choice < 1 || menu_choice > 3 { println!("(-) Input outside of bounds"); return;}

        if menu_choice == 1{
           decrypt_new_password(vector, keychain); 
        }else if menu_choice == 2 {

        }else{

        }
    }

    

}

                                                                            /* DECRYPTION AND ENCRYPTION FN */


// Encrypts the text and prints the encrypted data in hexadecimal
fn encrypt_text(key: &[u8], text: &str) -> String {
    // Generate random IV
    let mut iv = [0u8; 16];
    rand_bytes(&mut iv).expect("Failed to generate random IV");

    // Create the cipher
    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();

    // Encrypt the text
    let mut encrypted_data = cipher.encrypt_vec(text.as_bytes());
    encrypted_data = [&iv[..], &encrypted_data[..]].concat();

    // Print the encrypted data in hexadecimal
    let encrypted_hex = hex::encode(encrypted_data);
    println!("Encrypted data: {}", encrypted_hex);

    encrypted_hex
}

// Decrypts the text and prints the decrypted data
fn decrypt_text(key: &[u8], text: &str) -> Result<String, String> {
    // Parse the IV and ciphertext from the input
    let data = match hex::decode(text) {
        Ok(data) => data,
        Err(_) => {
            return Err("Invalid input data. Must be a valid hex-encoded string.".to_string());
        }
    };
    let (iv, ciphertext) = data.split_at(16);

    // Create the cipher
    let cipher = Aes256Cbc::new_from_slices(&key, iv).unwrap();

    // Decrypt the ciphertext
    let decrypted_data = match cipher.decrypt_vec(ciphertext) {
        Ok(data) => data,
        Err(_) => {
            return Err("Decryption failed. Ensure the provided password and encrypted data are correct.".to_string());
        }
    };

    // Convert to a string and return
    match String::from_utf8(decrypted_data) {
        Ok(text) => Ok(text),
        Err(_) => Err("Decrypted data contains invalid UTF-8 characters.".to_string()),
    }
}



                                                                            /* MISCELANEOUS FUNCTIONS */

//print out saved passwords as a function
fn print_saved_passwords(vector: &Vec<SessionPassword>){
    
    println!("\t\t+=============================================+");
    println!("\t\t+                Saved Passwords              +");
    println!("\t\t+=============================================+\n\n\n");

    for pass in vector {

        //count how many chars in username
        let char_count_user = pass.where_from.chars().count();
        let char_count_pass = pass.password.chars().count();
        
        //string for pass ***
        let mut string_for_privacy = String::new();

        
        for _ in 1..(53 - char_count_user){
            string_for_privacy.push('*');
        }

        println!("+=======================================================+");
        //println!("+{}: {}+", pass.where_from, pass.password);
        println!("+{}: {} +", pass.where_from, string_for_privacy);
        println!("+=======================================================+\n");

    }
}


//clears the screen
fn clear_screen(){
    for _i in 1..=50 { println!("\n"); }
}

//Returns a randomly generated set of chars as a String using rand::distributions::Alphanumeric
//SEE ABOVE
fn rand_chars() -> String{
    let mut rng = thread_rng();
    let chars: String = (0..22).map(|_| rng.sample(Alphanumeric) as char).collect();
    println!("Random chars: {}", chars);
    
    chars
}



                                                                            /*  TEST FUNCTIONS   */
//test fn to check for bycrypt functioning
#[test]
fn test_hashing(){

    /* 
    
    pub fn hash<P: AsRef<[u8]>>(password: P, cost: u32) -> BcryptResult<String>
    
    pub fn verify<P: AsRef<[u8]>>(password: P, hash: &str) -> BcryptResult<bool>

    cost: 4(min) - 31(max)

    DEFAULT_COST: 12
    
    */

    {
        let test_password = "123123";
        let hashed_test_pssw = hash(test_password, DEFAULT_COST).expect("(-) Failed to hash password");

        let hash_valid = verify(test_password, &hashed_test_pssw).expect("(-) Failed to verify password");

        assert_eq!(hash_valid, true, "(-) Failed at asserting hash and verify");
    }

    {
        let test_password = "u.9,6Pjz;YdV)Z@Cv^LeW2";
        let hashed_test_pssw = hash(test_password, DEFAULT_COST).expect("(-) Failed to hash password");

        let hash_valid = verify(test_password, &hashed_test_pssw).expect("(-) Failed to verify password");

        assert_eq!(hash_valid, true, "(-) Failed at asserting hash and verify");
    }

}

//test fn to assert encrypt and decrypt fns

#[test]
fn check_enc_dec() {
    {
        /*
         *
         * MISSING DOCUMENTATION FOR:
         * ENCRYPT_VEC
         * DECRYPT_VEC
         *
         * */
        let test_password = "f3cYsJn$uHv*}';R{X?8@2";
        let key = Sha256::digest("T[+U7m~qujn=HkbQcJ>`Y#".as_bytes());

        let encrypted = encrypt_text(&key, test_password);
        let decrypted = decrypt_text(&key, &encrypted).expect("Decryption failed");

        assert_eq!(decrypted, test_password, "Encryption and decryption did not work correctly");
    }
}

