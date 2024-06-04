extern crate bcrypt;

use bcrypt::{hash, verify, DEFAULT_COST};
use std::io;

fn main() {

    println!("+-----------------------------------+");
    println!("+           Password Manager        +");
    println!("+-----------------------------------+\n\n");
    


    println!("This is a simple password manager program which lets users securely store, manage, 
    and retrieve passwords. This project uses the bcrypt library to hash and validate passwords, 
    ensuring that user data is secure.\n\n");
    
    //main menu
    println!("1. Hash new password\n2. Exit\n");

    let mut menu_choice : u8;

    loop {
        //String for user input
        let mut user_input = String::new();

        io::stdin().read_line(&mut user_input).expect("(-) Failed to read line");

        //int for parse
        menu_choice = match user_input.trim().parse() { Ok(n) => n, Err(_) => { println!("(-) Not a valid number"); continue;} };


        if menu_choice < 1 || menu_choice > 2 {
            println!("Number outside of bounds..... try again\n");
        } else {
            break;
        }
    }

    if menu_choice == 1 {
        //go to fn
        get_user_input();
    } else { 
        println!("Exiting....\n");
        return;
    }
    
    /*
    let test_password = "123123123";

    let hash_password = hash(test_password, DEFAULT_COST).expect("Failed to hash password");
    let _ = verify(test_password, &hash_password);
    println!("Password: {}", test_password);
    println!("Hashed password: {}\n", hash_password);

    get_user_input();
    */
}

fn get_user_input(){

    println!("\nPlease input a password: ");
    
    //create a buffer
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer).expect("(-) Failed at reading stdin");
    //println!("{}", buffer.trim());
    

    //let buffer_ref: &str = &buffer.trim();

    let hashed_password = hash(buffer.clone(), DEFAULT_COST).expect("(-) Failed password hashing");
    let true_hash = verify(buffer.clone(), &hashed_password).expect("(-) Failed at asserting hash and verify");
    assert_eq!(true_hash, true);

    println!("Password: {} \nHashed: {}\n", buffer, hashed_password);

}

#[test]
fn test_hashing(){
    
    //costs for the hash function 4-31
    //DEFAULT_COST = 12

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
