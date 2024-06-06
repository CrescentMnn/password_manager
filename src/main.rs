extern crate bcrypt;
extern crate aes;
extern crate block_modes;
extern crate sha2;

use aes::Aes256;
use block_modes::{BlockMode, Cbc, block_padding::Pkcs7};
use sha2::{Digest, Sha256};
use std::env;
use openssl::rand::rand_bytes;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

//cryptography crate
use bcrypt::{hash, verify, DEFAULT_COST};

//input and output library
use std::io;

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
            .field("password", &"***********") // Mask the password for security reasons
            .finish()
    }
}

fn main() {

    clear_screen();
    println!("\t\t+=============================================+");
    println!("\t\t+            Password Manager  v.1.0          +");
    println!("\t\t+=============================================+\n\n\n");

    println!("This is a simple password manager program which lets users securely store, manage, 
and retrieve passwords. This project uses the bcrypt library to hash and validate passwords, 
ensuring that user data is secure.\n\n");
    
    //main menu
    println!("1. Hash new password\n2. Exit\n");

    let mut menu_choice : u8;

    //vector for passwords
    let mut passwords_vector : Vec<SessionPassword> = Vec::new();

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

        if menu_choice < 1 || menu_choice > 2 {
            println!("Number outside of bounds..... try again\n");
        } else {
            break;
        }
    }

    if menu_choice == 1 {
        //go to fn
        hash_new_password(&mut passwords_vector);
        println!("{:?}", passwords_vector);
    } else { 
        println!("Exiting....\n");
        return;
    }
    
}

fn hash_new_password(store: &mut Vec<SessionPassword>){

    clear_screen();
    println!("\t\t+=============================================+");
    println!("\t\t+               Hashing Passwords             +");
    println!("\t\t+=============================================+\n\n\n");

    println!("\nYou will have to create a username and give a password for further reading and creating password.\n");
    
    //username and password for programm
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
    }

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

        for _i in 1..=passwords_to_create {

            println!("\nUsername/Url: ");
            //create a buffer for username
            let mut buffer = String::new();
            io::stdin().read_line(&mut buffer).expect("(-) Failed at reading stdin");
            
            let username = buffer.trim().to_string();

            println!("\nPlease input a password: ");

            let mut pass_buffer = String::new();
            io::stdin().read_line(&mut pass_buffer).expect("(-) Failed at reading stdin");

            let new_password = pass_buffer.trim().to_string();
            let hashed_new_password = hash(new_password, DEFAULT_COST).expect("(-) Failed at hash of new password");
            
            //struct instance
            let new_user_password = SessionPassword { where_from: username, password: hashed_new_password, };
            
            store.push(new_user_password);

        }
    }
}

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
// Decrypts the text and returns the decrypted data
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

//asks for password, generates key and calls encrypt fn
fn encrypt_new_password(){



}

//retrieves key and hex string to decrypt, calls decrypt fn
fn decrypt_new_password(){
    
    

}

//clears the screen
fn clear_screen(){
    for _i in 1..=50 { println!("\n"); }
}

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
         *
         *
         * */
        let test_password = "f3cYsJn$uHv*}';R{X?8@2";
        let key = Sha256::digest("T[+U7m~qujn=HkbQcJ>`Y#".as_bytes());

        let encrypted = encrypt_text(&key, test_password);
        let decrypted = decrypt_text(&key, &encrypted).expect("Decryption failed");

        assert_eq!(decrypted, test_password, "Encryption and decryption did not work correctly");
    }
}

