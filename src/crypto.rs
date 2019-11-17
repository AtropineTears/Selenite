// Encodings
use base64;
use hex;

// Serialization
use serde::{Serialize, Deserialize};

// Hashing
use blake2_rfc::blake2b::{blake2b};

// PQcrypto
use pqcrypto_traits::sign::{PublicKey,SecretKey,DetachedSignature,VerificationError};
use pqcrypto_falcon::falcon512;
use pqcrypto_falcon::falcon1024;
use pqcrypto_sphincsplus::sphincsshake256256srobust;
use pqcrypto_qtesla::qteslapiii;




//=============================================================================================================================

/// # Traits For Keypairs
/// 
/// These traits are required to access the methods of the Keypair Structs. They implement basic functionality like conversion from hexadecimal to bytes, serializing/deserializing content, and signing inputs.
pub trait Keypairs {    
    /// ## Algorithm
    /// Shows the Algorithm For The Keypair Being Used
    const ALGORITHM: &'static str;
    /// ## Version
    /// Returns The Version
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
    /// ## Serializes To YAML
    /// This will serialize the contents of the keypair to YAML Format, which can be read with the import function.
    fn export(&self) -> String;
    /// ## Construct Keypair From YAML
    /// This function will deserialize the keypair into its respected struct.
    fn import(yaml: &str) -> Self;
    /// Return As Bytes
    #[deprecated]
    fn as_bytes(&self) -> (Vec<u8>,Vec<u8>);
    fn public_key_as_bytes(&self) -> Vec<u8>;
    fn secret_key_as_bytes(&self) -> Vec<u8>;
    /// ## Keypair Signing
    /// Allows Signing of an Input Using The Keyholder's Secret Key and Returns The Struct Signature.
    fn sign(&self,message: &str) -> Signature;
}
/// # Traits For Signatures
/// 
/// These traits are required for properly handling signatures. They allow the serialization/deserialization of signatures, the conversion into bytes, and the verification of signatures.
pub trait Signatures {
    fn export(&self) -> String;
    fn import(yaml: &str) -> Self;
    fn verify(&self) -> bool;
    fn signature_as_bytes(&self) -> Vec<u8>;
    fn message_as_bytes(&self) -> &[u8];
}
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default)]
struct qTeslaKeypair {
    pub algorithm: String,
    pub public_key: String,
    pub private_key: String,
    pub fingerprint: String,
    pub version: String,
}
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default)]
pub struct SphincsKeypair {
    pub algorithm: String,
    pub public_key: String,
    pub private_key: String,
    pub fingerprint: String,
    pub version: String,
}
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default)]
pub struct Falcon1024Keypair {
    pub algorithm: String,
    pub public_key: String,
    pub private_key: String,
    pub fingerprint: String,
    pub version: String,
}
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default)]
pub struct Falcon512Keypair {
    pub algorithm: String,
    pub public_key: String,
    pub private_key: String,
    pub fingerprint: String,
    pub version: String,
}
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default)]
pub struct Signature {
    pub algorithm: String,
    pub public_key: String,
    pub fingerprint: String,
    pub message: String,
    pub signature: String,
    pub version: String,
}


impl Keypairs for Falcon512Keypair {
    const VERSION: &'static str = "1.00";
    const ALGORITHM: &'static str = "FALCON512";
    const PUBLIC_KEY_SIZE: usize = 897;
    const SECRET_KEY_SIZE: usize = 1281;
    const SIGNATURE_SIZE: usize = 660;
    
    fn new() -> Self {
        let (pk,sk) = falcon512::keypair();
        let hash = blake2b(64,&[],hex::encode_upper(pk.as_bytes()).as_bytes());

        Falcon512Keypair {
            algorithm: String::from(Self::ALGORITHM),
            public_key: hex::encode_upper(pk.as_bytes()),
            private_key: hex::encode_upper(sk.as_bytes()),
            fingerprint: hex::encode_upper(hash.as_bytes()),
            version: String::from(Self::VERSION),
        }
    }
    fn export(&self) -> String {
        return serde_yaml::to_string(&self).unwrap();
    }
    // Add Error-Checking
    fn import(yaml: &str) -> Self {
        let result: Falcon512Keypair = serde_yaml::from_str(yaml).unwrap();
        return result
    }
    fn as_bytes(&self) -> (Vec<u8>,Vec<u8>){
        return (hex::decode(&self.public_key).unwrap(), hex::decode(&self.private_key).unwrap())
    }
    fn public_key_as_bytes(&self) -> Vec<u8> {
        return hex::decode(&self.public_key).unwrap()
    }
    fn secret_key_as_bytes(&self) -> Vec<u8> {
        return hex::decode(&self.private_key).unwrap()
    }
    fn sign(&self,message: &str) -> Signature {
        let x = falcon512::detached_sign(message.as_bytes(), &falcon512::SecretKey::from_bytes(&self.secret_key_as_bytes()).unwrap());
        
        return Signature {
            algorithm: String::from(Self::ALGORITHM), // String
            public_key: self.public_key.clone(), // Public Key Hex
            fingerprint: String::from(&self.fingerprint),
            message: String::from(message), // Original UTF-8 Message
            signature: base64::encode(x.as_bytes()), // Base64-Encoded Detatched Signature
            version: String::from(Self::VERSION),
        }
    }
}
impl Keypairs for Falcon1024Keypair {
    const VERSION: &'static str = "1.00";
    const ALGORITHM: &'static str = "FALCON1024";
    const PUBLIC_KEY_SIZE: usize = 1793;
    const SECRET_KEY_SIZE: usize = 2305;
    const SIGNATURE_SIZE: usize = 1280;
    
    fn new() -> Self {
        let (pk,sk) = falcon1024::keypair();
        let hash = blake2b(64,&[],hex::encode_upper(pk.as_bytes()).as_bytes());

        Falcon1024Keypair {
            algorithm: String::from(Self::ALGORITHM),
            public_key: hex::encode_upper(pk.as_bytes()),
            private_key: hex::encode_upper(sk.as_bytes()),
            fingerprint: hex::encode_upper(hash.as_bytes()),
            version: String::from(Self::VERSION)
        }
    }
    fn export(&self) -> String {
        return serde_yaml::to_string(&self).unwrap();
    }
    // Add Error-Checking
    fn import(yaml: &str) -> Self {
        let result: Falcon1024Keypair = serde_yaml::from_str(yaml).unwrap();
        return result
    }
    fn as_bytes(&self) -> (Vec<u8>,Vec<u8>){
        return (hex::decode(&self.public_key).unwrap(), hex::decode(&self.private_key).unwrap())
    }
    fn public_key_as_bytes(&self) -> Vec<u8> {
        return hex::decode(&self.public_key).unwrap()
    }
    fn secret_key_as_bytes(&self) -> Vec<u8> {
        return hex::decode(&self.private_key).unwrap()
    }
    fn sign(&self,message: &str) -> Signature {
        let x = falcon1024::detached_sign(message.as_bytes(), &falcon1024::SecretKey::from_bytes(&self.secret_key_as_bytes()).unwrap());
        
        return Signature {
            algorithm: String::from(Self::ALGORITHM), // String
            public_key: self.public_key.clone(), // Public Key Hex
            fingerprint: String::from(&self.fingerprint),
            message: String::from(message), // Original UTF-8 Message
            signature: base64::encode(x.as_bytes()), // Base64-Encoded Detatched Signature
            version: String::from(Self::VERSION),
        }
    }
}
impl Keypairs for SphincsKeypair {
    const VERSION: &'static str = "1.00";
    const ALGORITHM: &'static str = "SPHINCS+";
    const PUBLIC_KEY_SIZE: usize = 64;
    const SECRET_KEY_SIZE: usize = 128;
    const SIGNATURE_SIZE: usize = 29_792;
    
    fn new() -> Self {
        let (pk,sk) = sphincsshake256256srobust::keypair();
        let hash = blake2b(64,&[],hex::encode_upper(pk.as_bytes()).as_bytes());

        SphincsKeypair {
            algorithm: String::from(Self::ALGORITHM),
            public_key: hex::encode_upper(pk.as_bytes()),
            private_key: hex::encode_upper(sk.as_bytes()),
            fingerprint: hex::encode_upper(hash.as_bytes()),
            version: String::from(Self::VERSION),
        }
    }
    fn export(&self) -> String {
        return serde_yaml::to_string(&self).unwrap();
    }
    // Add Error-Checking
    fn import(yaml: &str) -> Self {
        let result: SphincsKeypair = serde_yaml::from_str(yaml).unwrap();
        return result
    }
    fn as_bytes(&self) -> (Vec<u8>,Vec<u8>){
        return (hex::decode(&self.public_key).unwrap(), hex::decode(&self.private_key).unwrap())
    }
    fn public_key_as_bytes(&self) -> Vec<u8> {
        return hex::decode(&self.public_key).unwrap()
    }
    fn secret_key_as_bytes(&self) -> Vec<u8> {
        return hex::decode(&self.private_key).unwrap()
    }
    fn sign(&self,message: &str) -> Signature {
        let x = sphincsshake256256srobust::detached_sign(message.as_bytes(), &sphincsshake256256srobust::SecretKey::from_bytes(&self.secret_key_as_bytes()).unwrap());
        return Signature {
            algorithm: String::from(Self::ALGORITHM), // String
            public_key: self.public_key.clone(), // Public Key Hex
            fingerprint: String::from(&self.fingerprint),
            message: String::from(message), // Original UTF-8 Message
            signature: base64::encode(x.as_bytes()), // Base64-Encoded Detatched Signature
            version: String::from(Self::VERSION),
        }
    }
}
impl Keypairs for qTeslaKeypair {
    const VERSION: &'static str = "1.00";
    const ALGORITHM: &'static str = "qTesla";
    const PUBLIC_KEY_SIZE: usize = 38_432;
    const SECRET_KEY_SIZE: usize = 12_392;
    const SIGNATURE_SIZE: usize = 5_664;
    
    fn new() -> Self {
        let (pk,sk) = qteslapiii::keypair();
        let hash = blake2b(64,&[],hex::encode_upper(pk.as_bytes()).as_bytes());

        qTeslaKeypair {
            algorithm: String::from(Self::ALGORITHM),
            public_key: hex::encode_upper(pk.as_bytes()),
            private_key: hex::encode_upper(sk.as_bytes()),
            fingerprint: hex::encode_upper(hash.as_bytes()),
            version: String::from(Self::VERSION),
        }
    }
    fn export(&self) -> String {
        return serde_yaml::to_string(&self).unwrap();
    }
    // Add Error-Checking
    fn import(yaml: &str) -> Self {
        let result: qTeslaKeypair = serde_yaml::from_str(yaml).unwrap();
        return result
    }
    fn as_bytes(&self) -> (Vec<u8>,Vec<u8>){
        return (hex::decode(&self.public_key).unwrap(), hex::decode(&self.private_key).unwrap())
    }
    fn public_key_as_bytes(&self) -> Vec<u8> {
        return hex::decode(&self.public_key).unwrap()
    }
    fn secret_key_as_bytes(&self) -> Vec<u8> {
        return hex::decode(&self.private_key).unwrap()
    }
    fn sign(&self,message: &str) -> Signature {
        let x = qteslapiii::detached_sign(message.as_bytes(), &qteslapiii::SecretKey::from_bytes(&self.secret_key_as_bytes()).unwrap());
        
        return Signature {
            algorithm: String::from(Self::ALGORITHM), // String
            public_key: self.public_key.clone(), // Public Key Hex
            fingerprint: String::from(&self.fingerprint),
            message: String::from(message), // Original UTF-8 Message
            signature: base64::encode(x.as_bytes()), // Base64-Encoded Detatched Signature
            version: String::from(Self::VERSION),
        }
    }
}

impl Signatures for Signature {
    fn export(&self) -> String {
        return serde_yaml::to_string(&self).unwrap();
    }
    fn import(yaml: &str) -> Self {
        let result: Signature = serde_yaml::from_str(yaml).unwrap();
        return result
    }
    fn message_as_bytes(&self) -> &[u8] {
        return self.message.as_bytes()
    }
    fn signature_as_bytes(&self) -> Vec<u8> {
        return base64::decode(&self.signature).unwrap()
    }
    fn verify(&self) -> bool {
        if self.algorithm == "FALCON512" {
            let v: Result<(),VerificationError> = falcon512::verify_detached_signature(&falcon512::DetachedSignature::from_bytes(&base64::decode(&self.signature).unwrap()).unwrap(), &self.message.as_bytes(), &falcon512::PublicKey::from_bytes(&hex::decode(&self.public_key).unwrap()).unwrap());
            if v.is_err() {
                return false
            }
            else {
                return true
            }
        }
        else if self.algorithm == "FALCON1024" {
            let v: Result<(),VerificationError> = falcon1024::verify_detached_signature(&falcon1024::DetachedSignature::from_bytes(&base64::decode(&self.signature).unwrap()).unwrap(), &self.message.as_bytes(), &falcon1024::PublicKey::from_bytes(&hex::decode(&self.public_key).unwrap()).unwrap());
            if v.is_err() {
                return false
            }
            else {
                return true
            }
        }
        else if self.algorithm == "SPHINCS+" {
            let v: Result<(),VerificationError> = sphincsshake256256srobust::verify_detached_signature(&sphincsshake256256srobust::DetachedSignature::from_bytes(&base64::decode(&self.signature).unwrap()).unwrap(), &self.message.as_bytes(), &sphincsshake256256srobust::PublicKey::from_bytes(&hex::decode(&self.public_key).unwrap()).unwrap());
            if v.is_err() {
                return false
            }
            else {
                return true
            }
        }
        else if self.algorithm == "qTesla" {
            unimplemented!();
            //qteslapiii::verify_detached_signature(sig: &DetachedSignature, msg: &[u8], pk: &PublicKey)
        }
        else {
            panic!("Cannot Read Algorithm Type")
        }
    }
}