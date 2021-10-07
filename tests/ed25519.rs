use selenite::crypto::*;

#[test]
fn test_ed_sig(){
    let keypair = ED25519Keypair::new();
    let signature = keypair.sign("This message is being signed");
    let is_verified = signature.verify();

    println!("Is Verified: {}",is_verified);
}