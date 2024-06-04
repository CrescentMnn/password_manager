extern crate bcrypt;

use bcrypt::{hash, verify, DEFAULT_COST};

fn main() {
    let test_password = "123123123";

    let hash_password = hash(test_password, DEFAULT_COST).expect("Failed to hash password");
    let _ = verify(test_password, &hash_password);
    println!("Password: {}", test_password);
    println!("Hashed password: {}", hash_password);
}
