use selenite::crypto::*;

#[test]
fn test_ed_sig(){
    let keypair = ED25519Keypair::new();
    let mut signature = keypair.sign_str("This message is being signed");
    let is_verified = signature.verify();

    println!("Is Verified: {}",is_verified);
}

#[test]
#[should_panic]
fn test_invalid_ed25519(){
    let keypair = ED25519Keypair::new();
    let mut signature = keypair.sign_str("This message is signed.");
    signature.message = String::from("This message is invalid.");

    let is_valid: bool = signature.verify();
    if is_valid == false {
        panic!("Invalid")
    }
}