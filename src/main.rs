extern crate bcrypt;

use bcrypt::{hash, verify, DEFAULT_COST};

fn main() {
    let test_password = "123123123";

    let hash_password = hash(test_password, DEFAULT_COST).expect("Failed to hash password");
    let _ = verify(test_password, &hash_password);
    println!("Password: {}", test_password);
    println!("Hashed password: {}", hash_password);
}

#[test]
fn test_hashing(){

    {
        let test_password = "123123";
        let hashed_test_pssw = hash(test_password, DEFAULT_COST).expect("(-) Failed to hash password");

        let hash_valid = verify(test_password, &hashed_test_pssw).expect("(-) Failed to verify password");

        assert_eq!(hash_valid, true);
    }

    {
        let test_password = "u.9,6Pjz;YdV)Z@Cv^LeW2";
        let hashed_test_pssw = hash(test_password, DEFAULT_COST).expect("(-) Failed to hash password");

        let hash_valid = verify(test_password, &hashed_test_pssw).expect("(-) Failed to verify password");

        assert_eq!(hash_valid, true);
    }

}
