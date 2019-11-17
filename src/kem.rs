use pqcrypto_newhope::newhope1024cca::*;
use pqcrypto_traits::kem::{PublicKey,SecretKey,SharedSecret,Ciphertext};
use slice_as_array;

pub struct NewHopeInitiater {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}
impl NewHopeInitiater {
    fn new() -> Self {

        let (pk,sk) = keypair();

        pk.as_bytes().to_vec()
        sk.as_bytes().to_vec();

        NewHopeInitiater {
            public_key: pk_array,
            secret_key: sk_array,
        }


    }
    fn send(&self) -> [u8;1_824] {
        return self.public_key
    }
    fn recieve(&self, ct: [u8;2_208]) ->  {
        let x = decapsulate(&Ciphertext::from_bytes(&ct).unwrap(), &SecretKey::from_bytes(&self.secret_key).unwrap());
        return x.as_bytes()
    }
}
pub struct NewHopeReceiver {
    public_key: [u8;1_824],
    shared_secret: [u8;32],
}

pub fn main(){
    let (pk, sk) = keypair();
    let (ss1, ct) = encapsulate(&pk);
    let ss2 = decapsulate(&ct, &sk);
    assert!(ss1 == ss2);
    println!("PK: {}",public_key_bytes());
    println!("SK: {}",secret_key_bytes());
    println!("SHARED SECRET: {}",shared_secret_bytes());
    println!("CIPHERTEXT: {}",ciphertext_bytes());
    println!();
    println!("PK: {}",pk.as_bytes().len());
    println!("SK: {}",sk.as_bytes().len());
    println!("SHARED SECRET: {}",ss1.as_bytes().len());
    println!("CIPHERTEXT: {}", ct.as_bytes().len());
}