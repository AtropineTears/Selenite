//! # Selenite: A Core Crypto Module
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

// Errors
use std::path::Path;
use blake2_rfc::blake2b::Blake2bResult;
use crate::sel_errors::SeleniteErrors;

// Encodings
use base64;
use hex;

// Logging
use log::{warn,info,debug,error};

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

use blake2_rfc::blake2b::{Blake2b,blake2b};

use ed25519_dalek::*;

use std::io;
use std::io::Read;
use std::io::BufReader;
use std::fs::File;
use std::fs::read;

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
    BLS,
}

pub enum SignatureType {
    String,
    Bytes,
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

    fn return_public_key_as_hex(&self) -> String;
    fn return_secret_key_as_hex(&self) -> String;

    fn decode_from_hex(s: String) -> Result<Vec<u8>,SeleniteErrors>;
    /// ## Keypair Signing
    /// Allows Signing of an Input Using The Keyholder's Secret Key and Returns The Struct Signature.
    fn sign(&self,message: &str) -> Signature;

    /// ## Sign (with Hash)
    /// 
    /// Signing bytes using `sign_data()` with Hash takes as input a slice of bytes. It then signs the hash of the bytes as opposed to signing the actual bytes.
    fn sign_data<T: AsRef<[u8]>>(&self, data: T) -> Signature;

    /// ## Sign File
    /// 
    /// This method lets you sign a file by signing the file's hash.
    fn sign_file<T: AsRef<Path>>(&self, path: T) -> Result<Signature,SeleniteErrors>;

    /// ## Data as Hexadecimal Hash
    /// 
    /// This function takes the data as a vector of bytes
    fn data_as_hexadecimal_hash(data: &[u8]) -> String;
    /// ## Data as Hash (in bytes)
    /// 
    /// This function returns the hash of the data as a vector of bytes
    fn data_as_hash(data: &[u8]) -> Vec<u8>;

    /// ## From
    /// 
    /// Converts from hexadecimal public key + private key to the respected struct. Also requires the algorithm to be known.
    fn construct_from<T: AsRef<str>>(pk: T, sk: T) -> Self;
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

pub struct BLSAggregatedSignature {
    pk: Vec<String>,
    messages: Vec<String>,
    signature: String,
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
///     let mut sig = keypair.sign_str("message_to_sign");
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
///     let signature = keypair.sign_str("This message is being signed.");
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

/// ## BLS Curve
/// ### Description
/// 
/// The BLS Curve is an elliptic curve based crypto that is not post-quantum cryptography but provides **signature aggregation** that is useful in many applications.
/// ### Developer Notes
/// 
/// Instead of storing itself in a Hexadecimal String, the private key and public key is stored as a byte array
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

    pub is_str: bool,
}

pub struct Verify;

impl BLSKeypair {
    /// # Aggregation Function
    /// 
    /// **Note:** Signatures must be in Base64 format.
    /// 
    /// **Info:** Aggregation is only allowed for BLS (BLSKeypair).
    /// 
    /// ---
    /// 
    /// ### Description
    /// 
    /// This function aggregates (or combines) Base64-encoded signatures for BLS (`BLSKeypair`). This can be used to reduce the number of signatures into a single signature.
    /// 
    /// ---
    /// ### Errors
    /// 
    /// The function returns `SeleniteErrors::BLSAggregationFailed` if an error occurs. It will panic if no signatures are passed to the function. It will also panic if conversion and decoding fails.
    pub fn aggregate(signatures: Vec<String>) -> Result<bls_signatures::Signature, SeleniteErrors> {
        let num_of_signatures = signatures.len();
        let mut v: Vec<bls_signatures::Signature> = vec![];

        log::info!("[INFO] BLS: Aggregating Digital Signatures.");
        log::info!("[INFO] BLS: Aggregating {} Signatures Into A Single Signature.",num_of_signatures);

        if num_of_signatures == 0 {
            log::error!("[ERROR] BLS: No Signatures Provided To Aggregation Function. Operating Failed.");
            panic!("[BLS|0x0002] No Signatures Provided To Aggregation Function");
        }


        for sig in signatures {
            let decoded_sig = base64::decode(sig).expect("[BLS|0x0000] Failed To Decode From Base64 During Aggregation of Signatures");
            let final_signature = bls_signatures::Signature::from_bytes(&decoded_sig).expect("[BLS|0x0001] Failed To Convert To `bls_signature::Signature` when converting from bytes.");
            v.push(final_signature);
        }
        let aggregated_signature = bls_signatures::aggregate(&v);

        match aggregated_signature {
            Ok(bls_sig) => {
                log::info!("[INFO] BLS: Finished Aggregation of Signatures. No Problems Detected.");
                return Ok(bls_sig)
            }
            Err(_) => {
                log::error!("[ERROR] Failed To Aggregate Signatures For BLS Signatures.");
                return Err(SeleniteErrors::BLSAggregationFailed)
            }
        }
    }
}

impl Keypairs for BLSKeypair {
    const VERSION: usize = 0;
    const ALGORITHM: &'static str = "BLS";
    const PUBLIC_KEY_SIZE: usize = 48usize;
    const SECRET_KEY_SIZE: usize = 32usize;
    const SIGNATURE_SIZE: usize = 96usize;

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
        log::warn!("[WARN|0x1004] The Secret Key For a BLS Keypair Was Just Returned In Bytes Form");
        return self.private_key.clone()
    }
    fn return_public_key_as_hex(&self) -> String {
        return hex::encode_upper(&self.public_key)
    }
    fn return_secret_key_as_hex(&self) -> String {
        log::warn!("[WARN|0x1004] The Secret Key For a BLS Keypair Was Just Returned In Hexadecimal Form");
        return hex::encode_upper(&self.private_key)
    }
    fn decode_from_hex(s: String) -> Result<Vec<u8>,SeleniteErrors> {
        let h = hex::decode(s);
        match h {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SeleniteErrors::DecodingFromHexFailed)
        }
    }
    fn sign(&self,message: &str) -> Signature {
        let key = bls_signatures::PrivateKey::from_bytes(&self.private_key).expect("Failed To Deserialize Private Key For BLS");
        let signature = key.sign(message.as_bytes());

        // Encoded In Hexadecimal
        let final_signature = base64::encode(signature.as_bytes());
        let pk = hex::encode_upper(&self.public_key);

        return Signature {
            algorithm: self.algorithm.clone(),
            public_key: pk,
            message: String::from(message),
            signature: final_signature,
            is_str: true,
        }

    }
    // Signs hexadecimal string
    fn sign_data<T: AsRef<[u8]>>(&self,data: T) -> Signature {
        let key = bls_signatures::PrivateKey::from_bytes(&self.private_key).expect("[BLS|0x0003] Failed To Deserialize Private Key For BLS");
        let final_hash = Self::data_as_hexadecimal_hash(data.as_ref());

        // Sign Hash of Data
        let signature = key.sign(final_hash.clone());

        // Encoded In Hexadecimal and Base64
        let final_signature = base64::encode(signature.as_bytes());
        let pk = hex::encode_upper(&self.public_key);


        return Signature {
            algorithm: String::from(Self::ALGORITHM),
            public_key: pk,
            message: final_hash,
            signature: final_signature,
            is_str: false,
        }

    }
    // Signs hexadecimal string
    fn sign_file<T: AsRef<Path>>(&self, path: T) -> Result<Signature,SeleniteErrors> {
        let does_file_exist: bool = path.as_ref().exists();

        if does_file_exist == false {
            return Err(SeleniteErrors::FileDoesNotExist)
        }

        let key = bls_signatures::PrivateKey::from_bytes(&self.private_key).expect("Failed To Deserialize Private Key For BLS");

        
        let fbuffer = std::fs::read(path).expect("[Error] failed to open file");
        let hash = Self::data_as_hexadecimal_hash(&fbuffer);

        let signature = key.sign(&hash);

        return Ok(Signature {
            algorithm: String::from(Self::ALGORITHM),
            public_key: self.return_public_key_as_hex(),
            message: hash,
            signature: base64::encode(&signature.as_bytes()),
            is_str: false
        })

    }
    fn data_as_hexadecimal_hash(data: &[u8]) -> String {
        let hash: Blake2bResult = blake2b(64, &[], data);
        let hex_hash: String = hex::encode_upper(hash.as_bytes());
        return hex_hash
    }
    fn data_as_hash(data: &[u8]) -> Vec<u8> {
        let hash: Blake2bResult = blake2b(64, &[], data);
        let bytes: Vec<u8> = hash.as_bytes().to_vec();
        return bytes
    }
    fn construct_from<T: AsRef<str>>(pk: T, sk: T) -> Self {
        return Self {
            algorithm: String::from(Self::ALGORITHM),
            public_key: hex::decode(pk.as_ref()).expect("[Error] Failed To Decode Public Key From Hex"),
            private_key: hex::decode(sk.as_ref()).expect("[Error] Failed To Decode Secret Key From Hex"),
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
        log::warn!("[WARN|0x1003] The Secret Key For a ED25519 Keypair Was Just Returned In Bytes Form");
        return self.private_key.clone()
    }
    fn return_public_key_as_hex(&self) -> String {
        return hex::encode_upper(&self.public_key)
    }
    fn return_secret_key_as_hex(&self) -> String {
        log::warn!("[WARN|0x1003] The Secret Key For a ED25519 Keypair Was Just Returned In Hexadecimal Form");
        return hex::encode_upper(&self.private_key)
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
            is_str: true,
        }
    }
    // Signs Hexadecimal String
    fn sign_data<T: AsRef<[u8]>>(&self, data: T) -> Signature {
        // Hash Message As Blake2b (64 bytes)
        let final_message_hash = Self::data_as_hexadecimal_hash(data.as_ref());

        // Public Keys and Private Keys
        let mut vector1: Vec<u8> = self.private_key.clone();
        let mut vector2: Vec<u8> = self.public_key.clone();

        // Init Keypair Vector
        let mut vector_keypair: Vec<u8> = vec![];

        // Append To Vector
        vector_keypair.append(&mut vector1);
        vector_keypair.append(&mut vector2);

        // Keypair
        let keypair = ed25519_dalek::Keypair::from_bytes(&vector_keypair).unwrap();
        let sig: ed25519_dalek::Signature = keypair.sign(&final_message_hash.as_bytes());


        return Signature {
            algorithm: String::from(Self::ALGORITHM),
            public_key: hex::encode_upper(self.public_key.clone()),
            message: final_message_hash,
            signature: base64::encode(sig),

            is_str: false,
        }
    }
    // Signs Hexadecimal String
    fn sign_file<T: AsRef<Path>>(&self, path: T) -> Result<Signature,SeleniteErrors> {
        let does_file_exist: bool = path.as_ref().exists();

        if does_file_exist == false {
            return Err(SeleniteErrors::FileDoesNotExist)
        }

        let mut vector1: Vec<u8> = self.private_key.clone();
        let mut vector2: Vec<u8> = self.public_key.clone();

        // Init Keypair Vector
        let mut vector_keypair: Vec<u8> = vec![];
        // Append To Vector
        vector_keypair.append(&mut vector1);
        vector_keypair.append(&mut vector2);

        let keypair = ed25519_dalek::Keypair::from_bytes(&vector_keypair).unwrap();
        
        let fbuffer = std::fs::read(path).expect("[Error] failed to open file");
        let hash = Self::data_as_hexadecimal_hash(&fbuffer);

        let sig: ed25519_dalek::Signature = keypair.sign(&hash.as_bytes());


        return Ok(Signature {
            algorithm: String::from(Self::ALGORITHM),
            public_key: self.return_public_key_as_hex(),
            message: hash,
            signature: base64::encode(sig),
            is_str: false
        })
    }
    fn decode_from_hex(s: String) -> Result<Vec<u8>,SeleniteErrors> {
        let h = hex::decode(s);
        match h {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SeleniteErrors::DecodingFromHexFailed)
        }
    }
    fn data_as_hexadecimal_hash(data: &[u8]) -> String {
        let hash: Blake2bResult = blake2b(64, &[], data);
        let hex_hash: String = hex::encode_upper(hash.as_bytes());
        return hex_hash
    }
    fn data_as_hash(data: &[u8]) -> Vec<u8> {
        let hash: Blake2bResult = blake2b(64, &[], data);
        let bytes = hash.as_bytes().to_vec();
        return bytes
    }
    fn construct_from<T: AsRef<str>>(pk: T, sk: T) -> Self {
        return Self {
            algorithm: String::from(Self::ALGORITHM),
            public_key: hex::decode(pk.as_ref()).expect("[Error] Failed To Decode Public Key From Hex"),
            private_key: hex::decode(sk.as_ref()).expect("[Error] Failed To Decode Secret Key From Hex"),
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
        log::warn!("[WARN|0x1001] The Secret Key For a FALCON512 Keypair Was Just Returned In Bytes Form");
        return hex::decode(&self.private_key).unwrap()
    }
    fn sign(&self,message: &str) -> Signature {
        let x = falcon512::detached_sign(message.as_bytes(), &falcon512::SecretKey::from_bytes(&self.secret_key_as_bytes()).unwrap());
        
        return Signature {
            algorithm: String::from(Self::ALGORITHM), // String
            public_key: self.public_key.clone(), // Public Key Hex
            message: String::from(message), // Original UTF-8 Message
            signature: base64::encode(x.as_bytes()), // Base64-Encoded Detatched Signature
            is_str: true,
        }
    }
    // Signs Hexadecimal Hash (as bytes)
    fn sign_data<T: AsRef<[u8]>>(&self,data: T) -> Signature {
        let hex_hash = Self::data_as_hexadecimal_hash(data.as_ref());
        let signature = falcon512::detached_sign(hex_hash.as_bytes(), &falcon512::SecretKey::from_bytes(&self.secret_key_as_bytes()).unwrap());

        return Signature {
            algorithm: String::from(Self::ALGORITHM),
            public_key: self.public_key.clone(),
            message: hex_hash,
            signature: base64::encode(signature.as_bytes()),
            is_str: false,
        }
    }
    // Signs hexadecimal hash (as bytes)
    fn sign_file<T: AsRef<Path>>(&self,path: T) -> Result<Signature,SeleniteErrors> {
        let does_file_exist: bool = path.as_ref().exists();

        if does_file_exist == false {
            return Err(SeleniteErrors::FileDoesNotExist)
        }

        let fbuffer = std::fs::read(path.as_ref()).expect("[Error] failed to open file");
        let hash = Self::data_as_hexadecimal_hash(&fbuffer);

        let signature = falcon512::detached_sign(hash.as_bytes(), &falcon512::SecretKey::from_bytes(&self.secret_key_as_bytes()).unwrap());

        return Ok(Signature {
            algorithm: String::from(Self::ALGORITHM),
            public_key: self.return_public_key_as_hex(),
            message: hash,
            signature: base64::encode(signature.as_bytes()),
            is_str: false,
        })
    }
    fn decode_from_hex(s: String) -> Result<Vec<u8>,SeleniteErrors> {
        let h = hex::decode(s);
        match h {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SeleniteErrors::DecodingFromHexFailed)
        }
    }
    fn return_public_key_as_hex(&self) -> String {
        return self.public_key.clone()
    }
    fn return_secret_key_as_hex(&self) -> String {
        log::warn!("[WARN|0x1001] The Secret Key For a FALCON512 Keypair Was Just Returned In Hexadecimal Form");
        return self.private_key.clone()
    }
    fn data_as_hexadecimal_hash(data: &[u8]) -> String {
        let hash: Blake2bResult = blake2b(64, &[], data);
        let hex_hash: String = hex::encode_upper(hash.as_bytes());
        return hex_hash
    }
    fn data_as_hash(data: &[u8]) -> Vec<u8> {
        let hash: Blake2bResult = blake2b(64, &[], data);
        let bytes = hash.as_bytes();
        return bytes.to_vec()
    }
    fn construct_from<T: AsRef<str>>(pk: T, sk: T) -> Self {
        return Self {
            algorithm: String::from(Self::ALGORITHM),
            public_key: pk.as_ref().to_string(),
            private_key: sk.as_ref().to_string(),
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
        log::warn!("[WARN|0x1002] The Secret Key For a FALCON1024 Keypair Was Just Returned In Bytes Form");
        return hex::decode(&self.private_key).unwrap()
    }
    fn sign(&self,message: &str) -> Signature {
        let x = falcon1024::detached_sign(message.as_bytes(), &falcon1024::SecretKey::from_bytes(&self.secret_key_as_bytes()).unwrap());
        
        return Signature {
            algorithm: String::from(Self::ALGORITHM), // String
            public_key: self.public_key.clone(), // Public Key Hex
            message: String::from(message), // Original UTF-8 Message
            signature: base64::encode(x.as_bytes()), // Base64-Encoded Detatched Signature
            is_str: true,
        }
    }
    fn sign_data<T: AsRef<[u8]>>(&self,data: T) -> Signature {
        let hex_hash = Self::data_as_hexadecimal_hash(data.as_ref());
        let signature = falcon1024::detached_sign(hex_hash.as_bytes(), &falcon1024::SecretKey::from_bytes(&self.secret_key_as_bytes()).unwrap());

        return Signature {
            algorithm: String::from(Self::ALGORITHM),
            public_key: self.public_key.clone(),
            message: hex_hash,
            signature: base64::encode(signature.as_bytes()),
            is_str: false,
        }
    }
    fn sign_file<T: AsRef<Path>>(&self,path: T) -> Result<Signature,SeleniteErrors> {
        let does_file_exist: bool = path.as_ref().exists();

        if does_file_exist == false {
            return Err(SeleniteErrors::FileDoesNotExist)
        }

        let fbuffer = std::fs::read(path.as_ref()).expect("[Error] failed to open file");
        let hash = Self::data_as_hexadecimal_hash(&fbuffer);

        let signature = falcon1024::detached_sign(hash.as_bytes(), &falcon1024::SecretKey::from_bytes(&self.secret_key_as_bytes()).unwrap());

        return Ok(Signature {
            algorithm: String::from(Self::ALGORITHM),
            public_key: self.return_public_key_as_hex(),
            message: hash,
            signature: base64::encode(signature.as_bytes()),
            is_str: false,
        })
    }
    fn decode_from_hex(s: String) -> Result<Vec<u8>,SeleniteErrors> {
        let h = hex::decode(s);
        match h {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SeleniteErrors::DecodingFromHexFailed)
        }
    }
    fn return_public_key_as_hex(&self) -> String {
        return self.public_key.clone()
    }
    fn return_secret_key_as_hex(&self) -> String {
        log::warn!("[WARN|0x1002] The Secret Key For a FALCON1024 Keypair Was Just Returned In Hexadecimal Form");
        return self.private_key.clone()
    }
    fn data_as_hexadecimal_hash(data: &[u8]) -> String {
        let hash: Blake2bResult = blake2b(64, &[], data);
        let hex_hash: String = hex::encode_upper(hash.as_bytes());
        return hex_hash
    }
    fn data_as_hash(data: &[u8]) -> Vec<u8> {
        let hash: Blake2bResult = blake2b(64, &[], data);
        let bytes = hash.as_bytes();
        return bytes.to_vec()
    }
    fn construct_from<T: AsRef<str>>(pk: T, sk: T) -> Self {
        return Self {
            algorithm: String::from(Self::ALGORITHM),
            public_key: pk.as_ref().to_string(),
            private_key: sk.as_ref().to_string(),
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
        log::warn!("[WARN|0x1000] The Secret Key For a SPHINCS+ Keypair Was Just Returned In Byte Form");
        return hex::decode(&self.private_key).unwrap()
    }
    fn sign(&self,message: &str) -> Signature {
        let x = sphincsshake256256srobust::detached_sign(message.as_bytes(), &sphincsshake256256srobust::SecretKey::from_bytes(&self.secret_key_as_bytes()).unwrap());
        return Signature {
            algorithm: String::from(Self::ALGORITHM), // String
            public_key: self.public_key.clone(), // Public Key Hex
            message: String::from(message), // Original UTF-8 Message
            signature: base64::encode(x.as_bytes()), // Base64-Encoded Detatched Signature
            is_str: true,
        }
    }
    fn sign_data<T: AsRef<[u8]>>(&self,data: T) -> Signature {
        let hex_hash = Self::data_as_hexadecimal_hash(data.as_ref());
        let signature = sphincsshake256256srobust::detached_sign(hex_hash.as_bytes(), &sphincsshake256256srobust::SecretKey::from_bytes(&self.secret_key_as_bytes()).unwrap());

        return Signature {
            algorithm: String::from(Self::ALGORITHM),
            public_key: self.public_key.clone(),
            message: hex_hash,
            signature: base64::encode(signature.as_bytes()),
            is_str: false,
        }
    }
    fn sign_file<T: AsRef<Path>>(&self,path: T) -> Result<Signature,SeleniteErrors> {
        let does_file_exist: bool = path.as_ref().exists();

        if does_file_exist == false {
            return Err(SeleniteErrors::FileDoesNotExist)
        }

        let fbuffer = std::fs::read(path.as_ref()).expect("[Error] failed to open file");
        let hash = Self::data_as_hexadecimal_hash(&fbuffer);

        let signature = sphincsshake256256srobust::detached_sign(hash.as_bytes(), &sphincsshake256256srobust::SecretKey::from_bytes(&self.secret_key_as_bytes()).unwrap());

        return Ok(Signature {
            algorithm: String::from(Self::ALGORITHM),
            public_key: self.return_public_key_as_hex(),
            message: hash,
            signature: base64::encode(signature.as_bytes()),
            is_str: false,
        })
    }
    fn decode_from_hex(s: String) -> Result<Vec<u8>,SeleniteErrors> {
        let h = hex::decode(s);
        match h {
            Ok(v) => return Ok(v),
            Err(_) => return Err(SeleniteErrors::DecodingFromHexFailed)
        }
    }
    fn return_public_key_as_hex(&self) -> String {
        return self.public_key.clone()
    }
    fn return_secret_key_as_hex(&self) -> String {
        log::warn!("[WARN|0x1000] The Secret Key For a SPHINCS+ Keypair Was Just Returned In Hexadecimal Form");
        return self.private_key.clone()
    }
    fn data_as_hexadecimal_hash(data: &[u8]) -> String {
        let hash: Blake2bResult = blake2b(64, &[], data);
        let hex_hash: String = hex::encode_upper(hash.as_bytes());
        return hex_hash
    }
    fn data_as_hash(data: &[u8]) -> Vec<u8> {
        let hash: Blake2bResult = blake2b(64, &[], data);
        let bytes = hash.as_bytes();
        return bytes.to_vec()
    }
    fn construct_from<T: AsRef<str>>(pk: T, sk: T) -> Self {
        return Self {
            algorithm: String::from(Self::ALGORITHM),
            public_key: pk.as_ref().to_string(),
            private_key: sk.as_ref().to_string(),
        }
    }
}

impl Signatures for Signature {
    fn new(algorithm: &str, pk: &str, signature: &str, message: &str) -> Self {
        if algorithm == "SPHINCS+" || algorithm == "FALCON512" || algorithm == "FALCON1024" || algorithm == "ED25519" || algorithm == "BLS" {
            return Signature {
                algorithm: algorithm.to_owned(),
                public_key: pk.to_owned(),
                message: message.to_owned(),
                signature: signature.to_owned(),
                is_str: true,
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
        else if self.algorithm == "BLS" {
            let base64_decoded = base64::decode(&self.signature).expect("Failed To Decoded Base64 For BLS");
            let hex_decoded = hex::decode(&self.public_key).expect("Failed To Decode Hexadecimal");

            let pk = bls_signatures::PublicKey::from_bytes(&hex_decoded).expect("Failed To Convert From Bytes To Signature In Verification Function For Public Key");
            let signature = bls_signatures::Signature::from_bytes(&base64_decoded).expect("Failed To Convert From Bytes To Signature In Verification Function For Signature");

            let is_valid: bool = bls_signatures::verify_messages(&signature, &vec![self.message.as_bytes()], &[pk]);

            return is_valid
        }
        else {
            panic!("[Verification|0x0000] Invalid Algorithm Type")
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
            KeypairAlgorithms::BLS => "BLS",
        };

        log::info!("[INFO] Verifying Digital Signature: {}",&alg);
        log::info!("Public Key: {}",pk);
        log::info!("Signature: {}",signature);
        log::info!("Message: {}",message);

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
        else if alg == "BLS" {
            let pk = hex::decode(pk).expect("Failed To Decode Public Key For BLS");
            let sig = base64::decode(signature).expect("Failed To Decode Signature From Base64");
            let message_as_bytes = message.as_bytes();

            let final_pk = bls_signatures::PublicKey::from_bytes(&pk).expect("Failed To Convert To Public Key For BLS");
            let final_sig = bls_signatures::Signature::from_bytes(&sig).expect("Failed To Convert To Signature For BLS");

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