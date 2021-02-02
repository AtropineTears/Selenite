//! # Selenite: Lacuna's Core Crypto Module
//! 
//! Lacuna's Core Crypto Module consists of the structs of keypairs (FALCON512,FALCON1024,SPHINCS+), the signature struct, and most importantly the implemented traits.
//!
//! When viewing documentation for a struct, make sure to look at the documentation for the traits **Keypairs** and **Signatures** as these contain the implemented methods.
//!
//! ## Example Usage
//!
//! ```
//! use selenite::crypto::*;
//! 
//! fn main() {
//!     // Generates The Respected Keypair
//!     let keypair = SphincsKeypair::new();
//! 
//!     // Signs The Message as a UTF-8 Encoded String
//!     let mut sig = keypair.sign("message_to_sign");
//!     
//!     // Returns a boolean representing whether the signature is valid or not
//!     let is_verified = sig.verify();
//! }
//! ```
//! ## Serialization
//! 
//! Serde-yaml is implemented by default for the serialization/deserialization of the data to the human-readable .yaml format.
//! 
//! ## More Information
//! 
//! This library is built on bindings to pqcrypto, a portable, post-quantum, cryptographic library.

// Encodings
use base64;
use hex;

// Serialization
use serde::{Serialize, Deserialize};
use bincode;

// PQcrypto
use pqcrypto_traits::sign::{PublicKey,SecretKey,DetachedSignature,VerificationError};
use pqcrypto_falcon::falcon512;
use pqcrypto_falcon::falcon1024;
use pqcrypto_sphincsplus::sphincsshake256256srobust;


//===INFORMATION===
// All Serialization can be done through YAML
// Serialization For Signatures can be done through bincode

// [Keypair Structs]
// All Keypair Structs come with three fields all being strings
// - algorithm {FALCON512,FALCON1024,SPHINCS+}
// - public_key
// - private_key

// - Public Keys and Private Keys are encoded in hexadecimal;
// - The Signature of the Signatures struct is encoded in base64

//TODO
// - Fix bincode serialization parameter

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
    /// - FALCON512
    /// - FALCON1024
    /// - SPHINCS+
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
    // bincode implementations
    fn export_to_bincode(&self) -> Vec<u8>;
        // TODO: Think about changing the type to &[u8] for import
    fn import_from_bincode(serde_bincode: Vec<u8>) -> Self;
    
    /// Serializes To YAML
    fn export(&self) -> String;
    /// Deserializes From YAML
    fn import(yaml: &str) -> Self;
    /// Verifies a Signature
    fn verify(&self) -> bool;
    fn signature_as_bytes(&self) -> Vec<u8>;
    fn message_as_bytes(&self) -> &[u8];
    /// # [Security] Match Public Key
    /// This will match the public key in the struct to another public key you provide to make sure they are the same. The Public Key **must** be in **upperhexadecimal format**.
    fn match_public_key(&self, pk: String) -> bool;
    /// # [Security] Match Message
    /// This will match the message in the struct to the message you provide to make sure they are the same.
    fn match_message(&self,msg: String) -> bool;
    /// # [Security] Matches Signatures
    /// This will match the signature in the struct with a provided signature (in base64 format)
    fn match_signature(&self,signature: String) -> bool;
}

/// ## SPHINCS+ (SHAKE256) Keypair
/// 
/// When using this keypair or looking at its documentation, please look at its implemented trait **Keypairs** for its methods.
/// 
/// ```
/// use selenite::crypto::*;
/// 
/// fn main() {
///     // Generates The Respected Keypair
///     let keypair = SphincsKeypair::new();
/// 
///     // Signs The Message as a UTF-8 Encoded String
///     let mut sig = keypair.sign("message_to_sign");
///     
///     // Returns a boolean representing whether the signature is valid or not
///     let is_verified = sig.verify();
/// }
/// ```
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default)]
pub struct SphincsKeypair {
    pub algorithm: String,
    pub public_key: String,
    pub private_key: String,
}
/// ## Falcon1024 Keypair
/// 
/// When using this keypair or looking at its documentation, please look at its implemented trait **Keypairs** for its methods.
/// 
/// ```
/// use selenite::crypto::*;
/// 
/// fn main() {
///     // Generates The Respected Keypair
///     let keypair = Falcon1024Keypair::new();
/// 
///     // Signs The Message as a UTF-8 Encoded String
///     let mut sig = keypair.sign("message_to_sign");
///     
///     // Returns a boolean representing whether the signature is valid or not
///     let is_verified = sig.verify();
/// }
/// ```
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default)]
pub struct Falcon1024Keypair {
    pub algorithm: String,
    pub public_key: String,
    pub private_key: String,
}
/// ## Falcon512 Keypair
/// 
/// When using this keypair or looking at its documentation, please look at its implemented trait **Keypairs** for its methods.
/// 
/// ```
/// use selenite::crypto::*;
/// 
/// fn main() {
///     // Generates The Respected Keypair
///     let keypair = Falcon512Keypair::new();
/// 
///     // Signs The Message as a UTF-8 Encoded String
///     let mut sig = keypair.sign("message_to_sign");
///     
///     // Returns a boolean representing whether the signature is valid or not
///     let is_verified = sig.verify();
/// }
/// ```
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default)]
pub struct Falcon512Keypair {
    pub algorithm: String,
    pub public_key: String,
    pub private_key: String,
}
/// ## The Signature Struct
/// 
/// This struct contains the fields for signatures and implements the Signatures trait to allow methods on the struct.
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default)]
pub struct Signature {
    pub algorithm: String,
    pub public_key: String,
    pub message: String,
    pub signature: String,
}

pub struct Verify;


impl Keypairs for Falcon512Keypair {
    const VERSION: &'static str = "1.00";
    const ALGORITHM: &'static str = "FALCON512";
    const PUBLIC_KEY_SIZE: usize = 897;
    const SECRET_KEY_SIZE: usize = 1281;
    const SIGNATURE_SIZE: usize = 660;
    
    fn new() -> Self {
        let (pk,sk) = falcon512::keypair();
        //let hash = blake2b(64,&[],hex::encode_upper(pk.as_bytes()).as_bytes());

        Falcon512Keypair {
            algorithm: String::from(Self::ALGORITHM),
            public_key: hex::encode_upper(pk.as_bytes()),
            private_key: hex::encode_upper(sk.as_bytes()),
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
            message: String::from(message), // Original UTF-8 Message
            signature: base64::encode(x.as_bytes()), // Base64-Encoded Detatched Signature
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
        //let hash = blake2b(64,&[],hex::encode_upper(pk.as_bytes()).as_bytes());

        Falcon1024Keypair {
            algorithm: String::from(Self::ALGORITHM),
            public_key: hex::encode_upper(pk.as_bytes()),
            private_key: hex::encode_upper(sk.as_bytes()),
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
            message: String::from(message), // Original UTF-8 Message
            signature: base64::encode(x.as_bytes()), // Base64-Encoded Detatched Signature
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
        //let hash = blake2b(64,&[],hex::encode_upper(pk.as_bytes()).as_bytes());

        SphincsKeypair {
            algorithm: String::from(Self::ALGORITHM),
            public_key: hex::encode_upper(pk.as_bytes()),
            private_key: hex::encode_upper(sk.as_bytes()),
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
            message: String::from(message), // Original UTF-8 Message
            signature: base64::encode(x.as_bytes()), // Base64-Encoded Detatched Signature
        }
    }
}

impl Signatures for Signature {
    fn export_to_bincode(&self) -> Vec<u8> {
        return bincode::serialize(&self).unwrap();
    }
    fn import_from_bincode(serde_bincode: Vec<u8>) -> Self {
        return bincode::deserialize(&serde_bincode[..]).unwrap();
    }
    fn export(&self) -> String {
        return serde_yaml::to_string(&self).unwrap();
    }
    fn import(yaml: &str) -> Self {
        let result: Signature = serde_yaml::from_str(yaml).unwrap();
        return result
    }
    // Returns message as a byte array
    fn message_as_bytes(&self) -> &[u8] {
        return self.message.as_bytes()
    }
    // Returns Base64 decoded signature as a vector of bytes
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
        else {
            panic!("Cannot Read Algorithm Type")
        }
    }
    /// [Security] Match Public Key
    /// Public Key is Encoded In Upper Hexadecimal
    fn match_public_key(&self, pk: String) -> bool {
        if self.public_key == pk {
            return true
        }
        else {
            return false
        }
    }
    // Message is a UTF-8 Message / String
    fn match_message(&self, msg: String) -> bool {
        if self.message == msg {
            return true
        }
        else {
            return false
        }
    }
    // Signature Is Encoded in Base64
    fn match_signature(&self, signature: String) -> bool {
        if self.signature == signature {
            return true
        }
        else {
            return false
        }
    }
}