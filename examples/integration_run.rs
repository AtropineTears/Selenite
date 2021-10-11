extern crate selenite;
use selenite::crypto::*;

fn main(){
    let keypair = Falcon512Keypair::new();
    let mut sig = keypair.sign_str("Message1");
    sig.message = "Message2".to_string();
    let is_verified = sig.verify();
    println!("is_verified (should be false): {}",is_verified);
}