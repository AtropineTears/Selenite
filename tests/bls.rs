use selenite::crypto::*;

#[test]
fn bls_general(){
    let keypair = BLSKeypair::new();
    let signature = keypair.sign("This message is signed");
    let is_valid = signature.verify();

    assert!(is_valid);
}

#[test]
fn bls_wrong_message(){
    let keypair = BLSKeypair::new();
    let mut signature = keypair.sign("This message is signed");
    signature.message = String::from("This message id signed");

    let is_valid = signature.verify();

    println!("Is_Valid: {}",is_valid);

    assert!(!is_valid);
}

#[test]
fn bls_aggregate(){
    let keypair = BLSKeypair::new();
    let keypair2 = BLSKeypair::new();
    let keypair3 = BLSKeypair::new();

    let sig = keypair.sign("This message is first");
    let sig2 = keypair.sign("This message is second");
    let sig3 = keypair.sign("This message is third");

    println!("Sig1: {:?}",base64::decode(&sig.signature).expect("Failed"));

    let output_sig = BLSKeypair::aggregate(vec![sig.signature.clone(),sig2.signature.clone(),sig3.signature.clone()]).expect("Failed");
    println!("Output Sig: {:?}",output_sig)

}