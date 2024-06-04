extern crate bcrypt;

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

    println!("+-----------------------------------+");
    println!("+           Password Manager        +");
    println!("+-----------------------------------+\n\n");

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

    println!("Now please enter how many passwords you wish to create (MAX 255): ");

    {
        //store # of passwords user wishes to create
        let passwords_to_create : u8;

        //buffer for stdin
        let mut buffer = String::new();
        io::stdin().read_line(&mut buffer).expect("(-) Failed at reading stdin");


        // menu_choice = match user_input.trim().parse() { Ok(n) => n, Err(_) => { println!("(-) Not a valid number"); continue;} };
        //parse stidn 
        passwords_to_create = match buffer.trim().parse() { Ok(n) => n, Err(_) => {println!("(-) Not a valid number"); return;} };

        if passwords_to_create > 255 || passwords_to_create < 1 {
            println!("Input out of bounds!!\n");
            return;
        }

        for _i in 1..=passwords_to_create {

            println!("Username/Url: ");
            //create a buffer for username
            let mut buffer = String::new();
            io::stdin().read_line(&mut buffer).expect("(-) Failed at reading stdin");
            
            let username = buffer.trim().to_string();

            println!("\nPlease input a password: ");

            let mut pass_buffer = String::new();
            io::stdin().read_line(&mut pass_buffer).expect("(-) Failed at reading stdin");

            let new_password = pass_buffer.trim().to_string();
            
            //struct instance
            let new_user_password = SessionPassword { where_from: username, password: new_password, };
            
            store.push(new_user_password);

        }
    }
}

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
