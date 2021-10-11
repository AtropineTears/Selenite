//! # Selenite: Lacuna's Core Crypto Module
//! 
//! Lacuna's Core Crypto Module consists of the structs of keypairs (FALCON512,FALCON1024,SPHINCS+), the signature struct, and most importantly the implemented traits.
//!
//! When viewing documentation for a struct, make sure to look at the documentation for the traits **Keypairs** and **Signatures** as these contain the implemented methods.
//!
//! ## Security Warning
//! 
//! This code **is not** audited and just recomended for **educational purposes**. Feel free to look through the code and help me out with it as the code is a bit... rusty.
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
//! ## How To Use
//! 
//! This is based upon my beliefs. You may choose yourself.
//! 
//! **SPHINCS+** should be used for code signing as it is quite slow at signing/verifying but is based on some high security assumptions and has a high security bit level.
//! 
//! **FALCON512/FALCON1024** is comparable to **RSA2048/RSA4096** and is fast at signing/verifying. It produces much smaller signatures but has a larger public key size (but still quite small).
//! 
//! 
//! ## Serialization
//! 
//! Serde-yaml is implemented by default for the serialization/deserialization of the data to the human-readable .yaml format.
//! 
//! ## More Information
//! 
//! This library is built on bindings to **pqcrypto**, a portable, post-quantum, cryptographic library.
//! 
//! SPHINCS+ reaches a security bit level of **255 bytes** which is well over what is needed and is **Level 5**. I have plans in the future to reduce this so the signature size is smaller.
//! 
//! ## References
//! 
//! [pqcrypto-rust](https://github.com/rustpq/pqcrypto)
//! 
//! [SPHINCS+](https://sphincs.org/)
//! 
//! [SPHINCS+ REPO](https://github.com/sphincs/sphincsplus)
//! 
//! [Falcon-Sign](https://falcon-sign.info/)

// Encodings
use base64;
use hex;

// Serialization
use serde::{Serialize, Deserialize};
use bincode;

// PQcrypto Digital Signatures
use pqcrypto_traits::sign::{PublicKey,SecretKey,DetachedSignature,VerificationError};
use pqcrypto_falcon::falcon512;
use pqcrypto_falcon::falcon1024;
use pqcrypto_sphincsplus::sphincsshake256256srobust;

extern crate rand;
extern crate ed25519_dalek;

use rand::rngs::OsRng;
use ed25519_dalek::Keypair;

use bls_signatures::*;
use bls_signatures::Serialize as Ser;

use ed25519_dalek::*;

use crate::random::OsRandom;


use std::convert::TryInto;



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
/// # Algorithms
/// This enum lists the algorithms implemented in the crate.
/// - `SPHINCS_PLUS` uses SPHINCS+ (SHAKE256) (256s) (Robust). The algorithm itself is highly secure and reaches Level 5.
pub enum KeypairAlgorithms {
    FALCON512,
    FALCON1024,
    SPHINCS_PLUS,

    ED25519,
    BLS12_381,
}
/// # Traits For Keypairs
/// 
/// These traits are required to access the methods of the Keypair Structs. They implement basic functionality like conversion from hexadecimal to bytes, serializing/deserializing content, and signing inputs.
pub trait Keypairs {    
    /// ## Algorithm
    /// Shows the Algorithm For The Keypair Being Used
    const ALGORITHM: &'static str;
    /// ## Version
    /// Returns The Version. 0 for unstable test. 1 for first implementation.
    const VERSION: usize;
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
    fn serialize(&self) -> String;
    /// ## Construct Keypair From YAML
    /// This function will deserialize the keypair into its respected struct.
    fn deserialize(yaml: &str) -> Self;
    /// Return As Bytes
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
    fn new(algorithm: &str, pk: &str, signature: &str, message: &str) -> Self;
    // bincode implementations
    fn serialize_to_bincode(&self) -> Vec<u8>;
        // TODO: Think about changing the type to &[u8] for import
    fn deserialize_from_bincode(serde_bincode: Vec<u8>) -> Self;
    /// Serializes To YAML
    fn serialize(&self) -> String;
    /// Deserializes From YAML
    fn deserialize(yaml: &str) -> Self;
    /// Verifies a Signature
    fn verify(&self) -> bool;
    fn signature_as_bytes(&self) -> Vec<u8>;
    fn message_as_bytes(&self) -> &[u8];
    /// # [Security] Compare Public Key
    /// This will match the public key in the struct to another public key you provide to make sure they are the same. The Public Key **must** be in **upperhexadecimal format**.
    fn compare_public_key(&self, pk: String) -> bool;
    /// # [Security] Compare Message
    /// This will match the message in the struct to the message you provide to make sure they are the same.
    fn compare_message(&self,msg: String) -> bool;
    /// # [Security] Matches Signatures
    /// This will match the signature in the struct with a provided signature (in base64 format)
    fn compare_signature(&self,signature: String) -> bool;
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
/// ## ED25519 Keypair
/// 
/// ED25519 is an elliptic-curve based digital signature scheme that is used for signing messages securely.
/// 
/// It is not post-quantum cryptography but due to its small keypair/signatures and speed, it has been included in the library.
/// 
/// ```
/// use selenite::crypto::*;
/// 
/// fn main() {
///     let keypair = ED25519::new();
///     
///     let signature = keypair.sign("This message is being signed.");
/// 
///     let is_valid = signature.verify();
/// 
///     assert!(is_valid);
/// 
/// }
/// ```
#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default)]
pub struct ED25519Keypair {
    pub algorithm: String,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Serialize,Deserialize,Clone,Debug,PartialEq,PartialOrd,Hash,Default)]
pub struct BLSKeypair {
    pub algorithm: String,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
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

impl Keypairs for BLSKeypair {
    const VERSION: usize = 0;
    const ALGORITHM: &'static str = "BLS12_381";
    const PUBLIC_KEY_SIZE: usize = 0usize;
    const SECRET_KEY_SIZE: usize = 0;
    const SIGNATURE_SIZE: usize = 0;

    fn new() -> Self {
        let randomness = OsRandom::rand_64().expect("Failed To Get Randomness");
        let secret_key = bls_signatures::PrivateKey::new(randomness);

        let secret_key_bytes = secret_key.as_bytes();

        let public_key = secret_key.public_key().as_bytes();

        return Self {
            algorithm: String::from(Self::ALGORITHM),
            public_key: public_key,
            private_key: secret_key_bytes,
        }
    }
    fn serialize(&self) -> String {
        return serde_yaml::to_string(&self).unwrap()
    }
    fn deserialize(yaml: &str) -> Self {
        let result: BLSKeypair = serde_yaml::from_str(yaml).unwrap();
        return result
    }
    fn public_key_as_bytes(&self) -> Vec<u8> {
        return self.public_key.clone()
    }
    fn secret_key_as_bytes(&self) -> Vec<u8> {
        return self.private_key.clone()
    }
    fn sign(&self,message: &str) -> Signature {
        let key = bls_signatures::PrivateKey::from_bytes(&self.private_key).expect("Failed To Deserialize Private Key For BLS12_381");
        let signature = key.sign(message);

        // Encoded In Hexadecimal
        let final_signature = base64::encode(signature.as_bytes());
        let pk = hex::encode_upper(&self.public_key);

        return Signature {
            algorithm: self.algorithm.clone(),
            public_key: pk,
            message: String::from(message),
            signature: final_signature,
        }

    }
}

impl Keypairs for ED25519Keypair{
    const VERSION: usize = 0;
    const ALGORITHM: &'static str = "ED25519";
    const PUBLIC_KEY_SIZE: usize = 32;
    const SECRET_KEY_SIZE: usize = 32;
    const SIGNATURE_SIZE: usize = 64;

    fn new() -> Self {
        let mut csprng = OsRng{};
        let keypair: ed25519_dalek::Keypair = ed25519_dalek::Keypair::generate(&mut csprng);
        let bytes: [u8; 64] = keypair.to_bytes();

        let sk = &bytes[0..32];
        let pk = &bytes[32..64];

        return Self {
            algorithm: String::from("ED25519"),
            public_key: pk.to_vec(),
            private_key: sk.to_vec(),
        }
    }
    fn serialize(&self) -> String {
        return serde_yaml::to_string(&self).unwrap()
    }
    fn deserialize(yaml: &str) -> Self {
        let result: ED25519Keypair = serde_yaml::from_str(yaml).unwrap();
        return result
    }
    fn public_key_as_bytes(&self) -> Vec<u8> {
        return self.public_key.clone()
    }
    fn secret_key_as_bytes(&self) -> Vec<u8> {
        return self.private_key.clone()
    }
    fn sign(&self, message: &str) -> Signature {
        let mut vector1: Vec<u8> = self.private_key.clone();
        let mut vector2: Vec<u8> = self.public_key.clone();

        let mut vector_keypair: Vec<u8> = vec![];

        vector_keypair.append(&mut vector1);
        vector_keypair.append(&mut vector2);

        let keypair = ed25519_dalek::Keypair::from_bytes(&vector_keypair).unwrap();
        let sig: ed25519_dalek::Signature = keypair.sign(message.as_bytes());


        return Signature {
            algorithm: String::from(Self::ALGORITHM),
            public_key: hex::encode_upper(self.public_key.clone()),
            message: String::from(message),
            signature: base64::encode(sig),
        }
    }
}

impl Keypairs for Falcon512Keypair {
    const VERSION: usize = 0;
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
    fn serialize(&self) -> String {
        return serde_yaml::to_string(&self).unwrap();
    }
    // Add Error-Checking
    fn deserialize(yaml: &str) -> Self {
        let result: Falcon512Keypair = serde_yaml::from_str(yaml).unwrap();
        return result
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
    const VERSION: usize = 0;
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
    fn serialize(&self) -> String {
        return serde_yaml::to_string(&self).unwrap();
    }
    // Add Error-Checking
    fn deserialize(yaml: &str) -> Self {
        let result: Falcon1024Keypair = serde_yaml::from_str(yaml).unwrap();
        return result
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
    const VERSION: usize = 0;
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
    fn serialize(&self) -> String {
        return serde_yaml::to_string(&self).unwrap();
    }
    // Add Error-Checking
    fn deserialize(yaml: &str) -> Self {
        let result: SphincsKeypair = serde_yaml::from_str(yaml).unwrap();
        return result
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
    fn new(algorithm: &str, pk: &str, signature: &str, message: &str) -> Self {
        if algorithm == "SPHINCS+" || algorithm == "FALCON512" || algorithm == "FALCON1024" {
            return Signature {
                algorithm: algorithm.to_owned(),
                public_key: pk.to_owned(),
                message: message.to_owned(),
                signature: signature.to_owned(),
            }
        }
        else {
            panic!("AlgorithmWrong")
        }
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
        else if self.algorithm == "ED25519" {
            let base64_decoded = base64::decode(self.signature.clone()).unwrap();
            let hex_decoded = hex::decode(self.public_key.clone()).unwrap();
            
            let pk: ed25519_dalek::PublicKey = ed25519_dalek::PublicKey::from_bytes(&hex_decoded).unwrap();

            if base64_decoded.len() == 64 {
                let mut sig: [u8;64] = [0u8;64];
                let mut counter = 0usize;

                for i in base64_decoded {
                    sig[counter] = i;
                    counter += 1;
                }

                let signature = ed25519_dalek::Signature::new(sig);
                let output = pk.verify_strict(self.message.as_bytes(), &signature);
                
                match output {
                    Ok(_v) => return true,
                    Err(_e) => return false,
                }
            }
            else {
                return false
            }
        }
        else if self.algorithm == "BLS12_381" {
            let base64_decoded = base64::decode(&self.signature).expect("Failed To Decoded Base64 For BLS12_381");
            let hex_decoded = hex::decode(&self.public_key).expect("Failed To Decode Hexadecimal");

            let pk = bls_signatures::PublicKey::from_bytes(&hex_decoded).expect("Failed To Convert From Bytes To Signature In Verification Function For Public Key");
            let signature = bls_signatures::Signature::from_bytes(&base64_decoded).expect("Failed To Convert From Bytes To Signature In Verification Function For Signature");

            let is_valid: bool = bls_signatures::verify_messages(&signature, &vec![self.message.as_bytes()], &[pk]);

            return is_valid
        }
        else {
            panic!("Cannot Read Algorithm Type")
        }
    }
    fn deserialize(yaml: &str) -> Self {
        let result: Signature = serde_yaml::from_str(yaml).unwrap();
        return result
    }
    fn serialize(&self) -> String {
        return serde_yaml::to_string(&self).unwrap();
    }
    fn deserialize_from_bincode(serde_bincode: Vec<u8>) -> Self {
        return bincode::deserialize(&serde_bincode[..]).unwrap();
    }
    fn serialize_to_bincode(&self) -> Vec<u8> {
        return bincode::serialize(&self).unwrap();
    }
    // Returns message as a byte array
    fn message_as_bytes(&self) -> &[u8] {
        return self.message.as_bytes()
    }
    // Returns Base64 decoded signature as a vector of bytes
    fn signature_as_bytes(&self) -> Vec<u8> {
        return base64::decode(&self.signature).unwrap()
    }
    fn compare_public_key(&self, pk: String) -> bool {
        if self.public_key == pk {
            return true
        }
        else {
            return false
        }
    }
    // Message is a UTF-8 Message / String
    fn compare_message(&self, msg: String) -> bool {
        if self.message == msg {
            return true
        }
        else {
            return false
        }
    }
    // Signature Is Encoded in Base64
    fn compare_signature(&self, signature: String) -> bool {
        if self.signature == signature {
            return true
        }
        else {
            return false
        }
    }
}
impl Verify {
    /// ## Verification
    /// Verifies Signatures by constructing them and returns a boolean.
    /// 
    /// Currently does not allow verification of ED25519 (non pq crypto)
    pub fn new(algorithm: KeypairAlgorithms,pk: &str,signature: &str,message: &str) -> bool {
        let alg = match algorithm {
            KeypairAlgorithms::FALCON512 => "FALCON512",
            KeypairAlgorithms::FALCON1024 => "FALCON1024",
            KeypairAlgorithms::SPHINCS_PLUS => "SPHINCS+",
            
            // Not Post-Quantum
            KeypairAlgorithms::ED25519 => "ED25519",
            KeypairAlgorithms::BLS12_381 => "BLS12_381",
        };
        // PK (HEX) | SIG (BASE64) | MESSAGE 
        let pk_bytes = hex::decode(pk).unwrap();
        let signature_bytes = base64::decode(signature).unwrap();
        let message_bytes = message.as_bytes();

        if alg == "FALCON512" {
            let v: Result<(),VerificationError> = falcon512::verify_detached_signature(&falcon512::DetachedSignature::from_bytes(&signature_bytes).unwrap(), message_bytes, &falcon512::PublicKey::from_bytes(&pk_bytes).unwrap());
            if v.is_err() {
                return false
            }
            else {
                return true
            }
        }
        if alg == "FALCON1024" {
            let v: Result<(),VerificationError> = falcon1024::verify_detached_signature(&falcon1024::DetachedSignature::from_bytes(&signature_bytes).unwrap(), message_bytes, &falcon1024::PublicKey::from_bytes(&pk_bytes).unwrap());
            if v.is_err() {
                return false
            }
            else {
                return true
            }
        }
        else if alg == "SPHINCS+" {
            let v: Result<(),VerificationError> = sphincsshake256256srobust::verify_detached_signature(&sphincsshake256256srobust::DetachedSignature::from_bytes(&signature_bytes).unwrap(), message_bytes, &sphincsshake256256srobust::PublicKey::from_bytes(&pk_bytes).unwrap());
            if v.is_err() {
                return false
            }
            else {
                return true
            }
        }
        else if alg  == "ED25519" {
            let mut sig_array: [u8;64] = [0;64];

            let pk = hex::decode(pk).expect("Failed To Decode Public Key For ED25519");
            let sig = base64::decode(signature).expect("Failed To Decode Signature From Base64 For ED25519");
            let message_as_bytes = message.as_bytes();

            for x in 0..sig.len() {
                sig_array[x] = sig[x];
            }

            let pk: ed25519_dalek::PublicKey = ed25519_dalek::PublicKey::from_bytes(&pk).expect("Failed To Convert To Public Key For ED25519");
            let signature: ed25519_dalek::Signature = ed25519_dalek::Signature::new(sig_array);

            let is_valid = pk.verify_strict(&message_as_bytes, &signature);
            match is_valid {
                Ok(_) => return true,
                Err(_) => return false,
            }
        }
        else if alg == "BLS12_381" {
            let pk = hex::decode(pk).expect("Failed To Decode Public Key For BLS12_381");
            let sig = base64::decode(signature).expect("Failed To Decode Signature From Base64");
            let message_as_bytes = message.as_bytes();

            let final_pk = bls_signatures::PublicKey::from_bytes(&pk).expect("Failed To Convert To Public Key For BLS12_381");
            let final_sig = bls_signatures::Signature::from_bytes(&sig).expect("Failed To Convert To Signature For BLS12_381");

            let is_valid: bool = bls_signatures::verify_messages(&final_sig, &vec![message_as_bytes], &[final_pk]);

            return is_valid
        }
        else {
            panic!("Cannot Read Algorithm Type")
        }
    }
    /// ## Determines Public Key Algorithm
    /// This determines the public key algorithm based on its key size (in hexadecimal) and returns a `KeypairAlgorithm` enum.
    pub fn determine_algorithm(pk: &str) -> KeypairAlgorithms {
        let length = pk.len();

        if length == 128 {
            return KeypairAlgorithms::SPHINCS_PLUS
        }
        else if length > 1500 && length < 2000 {
            return KeypairAlgorithms::FALCON512
        }
        else {
            return KeypairAlgorithms::FALCON1024
        }
    }
}