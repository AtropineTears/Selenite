use selenite::crypto::*;

fn main(){
    // [Generation] Generate a SPHINCS+ Keypair 
    let keypair = SphincsKeypair::new();

    // [Signing] Example of Signing a Blake2b Hash (32-bytes)
    let signature = keypair.sign_str("51C5300BF536636373E8F776A8BF48B9F527488C9B95C06E1A98C24B8C25CC47");
    
    // [Verification] Check If Signature Is Verified
    let is_verified = signature.verify();
    
    // [Output] I/O For Whether The Signature Is Valid (True/False)
    println!("Verified: {}",is_verified);
}