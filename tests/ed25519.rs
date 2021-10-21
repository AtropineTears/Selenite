use selenite::crypto::*;

#[test]
fn test_ed_sig(){
    let keypair = ED25519Keypair::new();
    let mut signature = keypair.sign("This message is being signed");
    let is_verified = signature.verify();

    assert!(is_verified);
}

#[test]
fn test_invalid_ed25519(){
    let keypair = ED25519Keypair::new();
    let mut signature = keypair.sign("This message is signed.");
    signature.message = String::from("This message is invalid.");

    let is_valid: bool = signature.verify();
    assert!(!is_valid);
}