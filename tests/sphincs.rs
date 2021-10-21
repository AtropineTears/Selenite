use selenite::crypto::*;

#[test]
fn sphincs_general(){
    let keypair = SphincsKeypair::new();
    let signature = keypair.sign("This message is signed");
    let is_valid_signature = signature.verify();
    assert!(is_valid_signature);
}

#[test]
fn sphincs_invalid_signature(){
    let keypair = SphincsKeypair::new();
    let mut signature = keypair.sign("This message is signed");
    signature.message = String::from("This message is sifned");
    let is_valid_signature = signature.verify();
    assert!(!is_valid_signature);
}

