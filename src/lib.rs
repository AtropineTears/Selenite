//! # Selenite
//! 
//! Lacuna's Core Library consists of all the core components for Lacuna.

// Denys The Usage of Unsafe Code and Allows non_camel_case_types 
#[allow(non_camel_case_types)]
#[deny(unsafe_code)]

/// The Core Module For Interacting With Keypairs/Signatures Through Their Traits.
pub mod constants;
pub mod sel_errors;

pub mod crypto;
pub mod certificate;
pub mod random;

//mod kem;

#[cfg(test)]
mod tests {
    use super::crypto::{Falcon512Keypair, Keypairs, Signatures, SphincsKeypair};
    //use super::kem;
    //use crypto::{Keypairs,Signatures};
    #[test]
    fn it_works() {
        // Generates a Falcon512 Keypair
        let keypair = Falcon512Keypair::new();
        
        // Exports To YAML
        let yaml = keypair.serialize();

        let x = Falcon512Keypair::deserialize(&yaml);

        println!("{}",x.public_key);
        println!();

        let sig = keypair.sign_str("Hello");
        sig.verify();
    }
    #[test]
    fn sphincs_plus(){
        let keypair = SphincsKeypair::new();
        let signature = keypair.sign_str("FFDE");
        signature.verify();
    }
    #[test]
    fn get_keypair_size(){
        let keypair = SphincsKeypair::new();
        let sig = keypair.sign_str("DJNASJNDASNJNJDSJNNJASDNJNJADSJNIDJNIJINEDJNNJIDENJDE");
        
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
