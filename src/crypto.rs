// Encodings
use base64;
use hex;

// Serialization
use serde::{Serialize, Deserialize};


use pqcrypto_traits::sign::{PublicKey,SecretKey,DetachedSignature,VerificationError};
use pqcrypto_falcon::falcon512;
use pqcrypto_falcon::falcon1024;
use pqcrypto_sphincsplus::sphincsshake256256srobust;


pub trait Keypairs {    
    /// ## Algorithm
    /// Shows the Algorithm For The Keypair Being Used
    const ALGORITHM: &'static str;
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
    fn construct<T: AsRef<str>>(pk: T, sk: T) -> Self;
    /// Return As Bytes
    fn as_bytes(&self) -> (Vec<u8>,Vec<u8>);
    /// Return Hexadecimal Public Key
    fn public_key(&self) -> String;
    /// Return Hexadecimal Private Key
    fn secret_key(&self) -> String;
    /// ## Keypair Signing
    /// Allows Signing of an Input Using The Keyholder's Secret Key and Returns The Struct Signature.
    fn sign(&self,input: &str) -> Signature;
}
pub trait Signatures {
    fn construct<T: AsRef<str>>(algorithm: T, pk: T, message: T, signature: T) -> Self;
    fn verify(&self);
    fn public_key(&self) -> String;
    fn message(&self) -> String;
    fn signature(&self) -> String;
    fn algorithm(&self) -> String;
}

#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default)]
pub struct SphincsKeypair {
    public: Vec<u8>,
    secret: Vec<u8>,
}
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default)]
pub struct Falcon1024Keypair {
    public: Vec<u8>,
    secret: Vec<u8>,
}
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default)]
pub struct Falcon512Keypair {
    public: Vec<u8>,
    secret: Vec<u8>,
}
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default)]
pub struct Signature {
    algorithm: String,
    public: String,
    input: String,
    signature: String,
}


impl Keypairs for Falcon512Keypair {
    const ALGORITHM: &'static str = "FALCON512";
    const PUBLIC_KEY_SIZE: usize = 897;
    const SECRET_KEY_SIZE: usize = 0;
    const SIGNATURE_SIZE: usize = 1274;
    
    fn new() -> Self {
        let (pk,sk) = falcon512::keypair();

        Falcon512Keypair {
            public: pk.as_bytes().to_vec(),
            secret: sk.as_bytes().to_vec(),
        }
    }
    fn export(&self) -> String {
        return serde_yaml::to_string(&self).unwrap();
    }
    fn construct<T: AsRef<str>>(pk: T,sk: T) -> Self {
        Falcon512Keypair {
            public: hex::decode(pk.as_ref()).unwrap(),
            secret: hex::decode(sk.as_ref()).unwrap(),
        }
    }
    // Remove The Clone If Possible
    fn as_bytes(&self) -> (Vec<u8>,Vec<u8>){
        return (self.public.clone(), self.secret.clone())
    }
    fn public_key(&self) -> String {
        return hex::encode_upper(&self.public)
    }
    fn secret_key(&self) -> String {
        return hex::encode_upper(&self.secret)
    }
    fn sign(&self,input: &str) -> Signature {
        let x = falcon512::detached_sign(input.as_bytes(), &falcon512::SecretKey::from_bytes(&self.secret).unwrap());
        
        return Signature {
            algorithm: String::from(Self::ALGORITHM), // String
            public: self.public_key(), // Public Key Hex 
            input: String::from(input), // Original UTF-8 Message
            signature: base64::encode(x.as_bytes()), // Base64-Encoded Detatched Signature
        }
    }
}

impl Signatures for Signature {
    fn construct<T: AsRef<str>>(algorithm: T, pk: T, message: T, signature: T) -> Self {
        let alg = algorithm.as_ref();
        
        if alg == "FALCON512" || alg == "FALCON1024" || alg == "SPHINCS+" {
            return Signature {
                algorithm: String::from(alg),
                public: String::from(pk.as_ref()),
                input: String::from(message.as_ref()),
                signature: String::from(signature.as_ref()),
            }
        }
        else {
            panic!("No Supported Algorithm Detected")
        }
        
    }
    fn verify(&self) {
        if self.algorithm == "FALCON512" {
            falcon512::verify_detached_signature(&falcon512::DetachedSignature::from_bytes(&base64::decode(&self.signature).unwrap()).unwrap(), &self.input.as_bytes(), &falcon512::PublicKey::from_bytes(&hex::decode(&self.public).unwrap()).unwrap()).unwrap();
        }
        else if self.algorithm == "FALCON1024" {
            falcon1024::verify_detached_signature(&falcon1024::DetachedSignature::from_bytes(&base64::decode(&self.signature).unwrap()).unwrap(), &self.input.as_bytes(), &falcon1024::PublicKey::from_bytes(&hex::decode(&self.public).unwrap()).unwrap()).unwrap();
        }
        else if self.algorithm == "SPHINCS+" {
            sphincsshake256256srobust::verify_detached_signature(&sphincsshake256256srobust::DetachedSignature::from_bytes(&base64::decode(&self.signature).unwrap()).unwrap(), &self.input.as_bytes(), &sphincsshake256256srobust::PublicKey::from_bytes(&hex::decode(&self.public).unwrap()).unwrap()).unwrap();
        }
        else {
            panic!("Cannot Read Algorithm Type")
        }
    }
    fn public_key(&self) -> String {
        return self.public.clone()
    }
    fn message(&self) -> String {
        return self.input.clone()
    }
    fn signature(&self) -> String {
        return self.signature.clone()
    }
    fn algorithm(&self) -> String {
        return self.algorithm.clone()
    }
}