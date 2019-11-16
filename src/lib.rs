#[allow(non_camel_case_types)]

pub mod crypto;

#[cfg(test)]
mod tests {
    use super::crypto::*;
    //use crypto::{Keypairs,Signatures};
    #[test]
    fn it_works() {
        // Generates a Falcon512 Keypair
        let keypair = Falcon512Keypair::new();
        
        let yaml = keypair.export();

        let x = Falcon512Keypair::import(&yaml);

        println!("{}",x.public_key);
        println!();

        let sig = keypair.sign("Hello");
        sig.verify();
    }
    #[test]
    fn sphincs_plus(){
        let keypair = SphincsKeypair::new();
        let signature = keypair.sign("FFDE");
        signature.verify();
    }
    #[test]
    fn get_keypair_size(){
        let keypair = SphincsKeypair::new();
        let sig = keypair.sign("DJNASJNDASNJNJDSJNNJASDNJNJADSJNIDJNIJINEDJNNJIDENJDE");
        
        let is_verified = sig.verify();
        
        let size_of_pk = keypair.public_key_as_bytes().len();
        let size_of_sk = keypair.secret_key_as_bytes().len();
        let size_of_signature = base64::decode(&sig.signature).unwrap().len();

        println!("Algorithm: {}",keypair.algorithm);
        println!("Size of PK: {}",size_of_pk);
        println!("Size of SK: {}",size_of_sk);
        println!("Size of Signature: {}",size_of_signature);
        println!("Signature is Verified: {}",is_verified);
    }
}
