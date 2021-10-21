use selenite::crypto::*;

#[test]
fn falcon512_general(){
    let keypair = Falcon512Keypair::new();
    let sig = keypair.sign("This message is signed.");
    let is_valid = sig.verify();
    assert!(is_valid);
}

#[test]
fn falcon512_wrong_message(){
    let keypair = Falcon512Keypair::new();
    let mut sig = keypair.sign("This message is signed.");
    sig.message = String::from("This message is sifned.");
    let is_valid = sig.verify();

    assert!(!is_valid);
}
