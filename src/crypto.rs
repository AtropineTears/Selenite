// Encodings
use base64;
use hex;

// Serialization
use serde::{Serialize, Deserialize};

use blake2_rfc::blake2b::{blake2b};


use pqcrypto_traits::sign::{PublicKey,SecretKey,DetachedSignature,VerificationError};
use pqcrypto_falcon::falcon512;
use pqcrypto_falcon::falcon1024;
use pqcrypto_sphincsplus::sphincsshake256256srobust;


pub trait Keypairs {    
    /// ## Algorithm
    /// Shows the Algorithm For The Keypair Being Used
    const ALGORITHM: &'static str;
    const VERSION: &'static str;
    const PUBLIC_KEY_SIZE: usize;
    const SECRET_KEY_SIZE: usize;
    const SIGNATURE_SIZE: usize;

    
    /// ## Generate A New Keypair
    /// Creates A New Keypair From Respected Struct Being Called.
    /// 
    /// Keypair Options:
    /// - **FALCON512**
    /// - **FALCON1024**
    /// - **SPHINCS+**
    fn new() -> Self;
    fn export(&self) -> String;
    /// ## Constructs A Keypair
    /// Construct Keypair From Hexadecimal String or str. This will not generate a new keypair.
    fn construct<T: AsRef<str>>(pk: T, sk: T, Fingerprint: T, Version: T) -> Self;
    /// Return As Bytes
    fn as_bytes(&self) -> (Vec<u8>,Vec<u8>);
    /// Return Hexadecimal Public Key
    fn public_key(&self) -> String;
    /// Return Hexadecimal Private Key
    fn secret_key(&self) -> String;
    fn public_key_as_bytes(&self) -> Vec<u8>;
    fn secret_key_as_bytes(&self) -> Vec<u8>;
    /// ## Keypair Signing
    /// Allows Signing of an Input Using The Keyholder's Secret Key and Returns The Struct Signature.
    fn sign(&self,Message: &str) -> Signature;
}
pub trait Signatures {
    fn construct<T: AsRef<str>>(Algorithm: T, pk: T, fingerprint: T, message: T, signature: T, Version: T) -> Self;
    fn verify(&self);
    fn public_key(&self) -> String;
    fn message(&self) -> String;
    fn signature(&self) -> String;
    fn algorithm(&self) -> String;
}

#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default)]
pub struct SphincsKeypair {
    Algorithm: String,
    PublicKey: String,
    PrivateKey: String,
    Fingerprint: String,
    Version: String,
}
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default)]
pub struct Falcon1024Keypair {
    Algorithm: String,
    PublicKey: String,
    PrivateKey: String,
    Fingerprint: String,
    Version: String,
}
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default)]
pub struct Falcon512Keypair {
    Algorithm: String,
    PublicKey: String,
    PrivateKey: String,
    Fingerprint: String,
    Version: String,
}
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default)]
pub struct Signature {
    Algorithm: String,
    PublicKey: String,
    Fingerprint: String,
    Message: String,
    Signature: String,
    Version: String,
}


impl Keypairs for Falcon512Keypair {
    const VERSION: &'static str = "1.00";
    const ALGORITHM: &'static str = "FALCON512";
    const PUBLIC_KEY_SIZE: usize = 897;
    const SECRET_KEY_SIZE: usize = 0;
    const SIGNATURE_SIZE: usize = 1274;
    
    fn new() -> Self {
        let (pk,sk) = falcon512::keypair();
        let hash = blake2b(64,&[],hex::encode_upper(pk.as_bytes()).as_bytes());

        Falcon512Keypair {
            Algorithm: String::from(Self::ALGORITHM),
            PublicKey: hex::encode_upper(pk.as_bytes()),
            PrivateKey: hex::encode_upper(sk.as_bytes()),
            Fingerprint: hex::encode_upper(hash.as_bytes()),
            Version: String::from("1.00")
        }
    }
    fn export(&self) -> String {
        return serde_yaml::to_string(&self).unwrap();
    }
    fn construct<T: AsRef<str>>(pk: T,sk: T, hash: T, Version: T) -> Self {
        Falcon512Keypair {
            Algorithm: String::from(Self::ALGORITHM),
            PublicKey: pk.as_ref().to_string(),
            PrivateKey: sk.as_ref().to_string(),
            Fingerprint: hash.as_ref().to_string(),
            Version: Version.as_ref().to_string()
        }
    }
    fn as_bytes(&self) -> (Vec<u8>,Vec<u8>){
        return (hex::decode(&self.PublicKey).unwrap(), hex::decode(&self.PrivateKey).unwrap())
    }
    fn public_key(&self) -> String {
        return self.PublicKey.clone()
    }
    fn secret_key(&self) -> String {
        return self.PrivateKey.clone()
    }
    fn public_key_as_bytes(&self) -> Vec<u8> {
        return hex::decode(&self.PublicKey).unwrap()
    }
    fn secret_key_as_bytes(&self) -> Vec<u8> {
        return hex::decode(&self.PrivateKey).unwrap()
    }
    fn sign(&self,Message: &str) -> Signature {
        let x = falcon512::detached_sign(Message.as_bytes(), &falcon512::SecretKey::from_bytes(&self.secret_key_as_bytes()).unwrap());
        
        return Signature {
            Algorithm: String::from(Self::ALGORITHM), // String
            PublicKey: self.public_key(), // Public Key Hex
            Fingerprint: String::from(&self.Fingerprint),
            Message: String::from(Message), // Original UTF-8 Message
            Signature: base64::encode(x.as_bytes()), // Base64-Encoded Detatched Signature
            Version: String::from(Self::VERSION),
        }
    }
}

impl Signatures for Signature {
    fn construct<T: AsRef<str>>(Algorithm: T, pk: T, fingerprint: T, message: T, Signature: T, Version: T) -> Self {
        let alg = Algorithm.as_ref();
        
        if alg == "FALCON512" || alg == "FALCON1024" || alg == "SPHINCS+" {
            return Signature {
                Algorithm: String::from(alg),
                PublicKey: String::from(pk.as_ref()),
                Fingerprint: String::from(fingerprint.as_ref()),
                Message: String::from(message.as_ref()),
                Signature: String::from(Signature.as_ref()),
                Version: String::from(Version.as_ref()),
            }
        }
        else {
            panic!("No Supported Algorithm Detected")
        }
        
    }
    fn verify(&self) {
        if self.Algorithm == "FALCON512" {
            falcon512::verify_detached_signature(&falcon512::DetachedSignature::from_bytes(&base64::decode(&self.Signature).unwrap()).unwrap(), &self.Message.as_bytes(), &falcon512::PublicKey::from_bytes(&hex::decode(&self.PublicKey).unwrap()).unwrap()).unwrap();
        }
        else if self.Algorithm == "FALCON1024" {
            falcon1024::verify_detached_signature(&falcon1024::DetachedSignature::from_bytes(&base64::decode(&self.Signature).unwrap()).unwrap(), &self.Message.as_bytes(), &falcon1024::PublicKey::from_bytes(&hex::decode(&self.PublicKey).unwrap()).unwrap()).unwrap();
        }
        else if self.Algorithm == "SPHINCS+" {
            sphincsshake256256srobust::verify_detached_signature(&sphincsshake256256srobust::DetachedSignature::from_bytes(&base64::decode(&self.Signature).unwrap()).unwrap(), &self.Message.as_bytes(), &sphincsshake256256srobust::PublicKey::from_bytes(&hex::decode(&self.PublicKey).unwrap()).unwrap()).unwrap();
        }
        else {
            panic!("Cannot Read Algorithm Type")
        }
    }
    fn public_key(&self) -> String {
        return self.PublicKey.clone()
    }
    fn message(&self) -> String {
        return self.Message.clone()
    }
    fn signature(&self) -> String {
        return self.Signature.clone()
    }
    fn algorithm(&self) -> String {
        return self.Algorithm.clone()
    }
}