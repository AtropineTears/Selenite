use selenite::crypto::*;

fn main(){
    // Generates a new Falcon512 Keypair (Alg,PK,SK)
    let keypair = Falcon512Keypair::new();

    // Generates a new Falcon1024 Keypaur (Alg,PK,SK)
    let keypair2 = Falcon1024Keypair::new();
    
    // Mutable Signature For Keypair To Sign "Hello World!" as UTF-8 String
    let mut signature = keypair.sign_str("Hello World!");
    
    // Change Message String From "Hello World!" to "Goodbye World!"
    signature.message = "Goodbye World!".to_string();

    // Check if signature is verified based on message, pk, signature
    let is_verified = signature.verify();
    
    // [Output] Should Be False As Message Is Tampered With
    println!("is_verified (should be false): {}",is_verified);
}