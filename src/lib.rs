pub mod crypto;
// Use Traits
use crypto::{Keypairs,Signatures};

#[cfg(test)]
mod tests {
    use super::crypto::*;
    //use crypto::{Keypairs,Signatures};
    #[test]
    fn it_works() {
        // Generates a Falcon512 Keypair
        let keypair = Falcon512Keypair::new();
        
        // Runs Methods on Falcon512
        let (pk,sk) = keypair.as_bytes();
        let pubkey = keypair.public_key();
        let secretkey = keypair.secret_key();
        
        let yaml = keypair.export();

        println!("FALCON512");
        println!("YAML: {}",yaml);
        println!();
        println!("PublicKey: {}",pubkey);
        println!();
        println!("SecretKey: {}",secretkey);

        let sig = keypair.sign("Hello");
        sig.verify();
    }
    #[test]
    fn falcon512_should_fail(){
        let keypair = Falcon512Keypair::new();
    }
}
