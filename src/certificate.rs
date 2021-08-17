// TODO
// - Test difference between blake2-rfc and blake2

// The Structure
// Basic Idea of Generation: PK (Hex) --> [Blake2b] Hash (Hex) --> ID (BASE32) | Sign with Private Key

// Encoding
use base32::{Alphabet,encode,decode};

// Hashing
use blake2_rfc::blake2b::{Blake2b,blake2b};

// Crypto
use crate::crypto::*;

// Serialization
use serde::{Serialize, Deserialize};

// Use Base32 (RFC 4648) and make sure its padded
// RFC 4648 states that padding must be used unless the specification of the standard referring to the RFC explicitly states otherwise.
// https://datatracker.ietf.org/doc/html/rfc4648

// Signing:
// Binaries should be signed with SPHINCS+ (Level 5)
// - SPHINCS+ Verfication is slow, usually taking a few seconds but it has high security margin and good crypto assumptions

/// Used for creating certificates.
pub enum Algorithms {
    FALCON512,
    FALCON1024,
    SPHINCS_PLUS
}

/// # String Formats
/// Used for Error-Checking and also used for quick access to the format.
pub enum StringFormats {
    BASE32,
    BASE64,
    HEXADECIMAL,
}

/// ## SphincsCertificate
/// A `SphincsCertificate` is a struct that contains:
/// * The `id` which is encoded in **base32** with characters [A-Z] and [1-7] based on the hash. It uses the **RFC4648 Format**.
/// * The `pk` (public key) which is encoded in **upper hexadecimal** and is **64 bytes**.
/// * The `hash` is a 64 byte hash using blake2b in hexadecimal. It is a hash of the public key (in bytes).
/// * The `signature` is a signature of the id,pk, and hash combined together.
/// 
/// The id is similar to the Serial Number
/// 
/// The Certificate should be used to **sign binaries** as it is **slow but very secure (assuming there are no vulnerabilties or side channel attacks)**.
#[derive(Serialize,Deserialize,Debug,Clone,PartialEq,PartialOrd,Hash,Default)]
pub struct SphincsCertificate {
    version: usize,
    id: String,
    hash: String,
    pk: String,
    signature_algorithm: String,
    signature: String,
}

impl SphincsCertificate {
    // 0 means test version where certificates can break between versions
    const VERSION: usize = 0;
    const BLAKE2B_DIGEST_SIZE: usize = 64;
    
    // STRING SIZES (in bytes)
    const STRING_ID_SIZE: usize = 104; // BASE32
    const STRING_PUBLIC_KEY_SIZE: usize = 128; // HEXADECIMAL
    const STRING_HASH_SIZE: usize = 128; // HEXADECIMAL
    const STRING_SIGNATURE_SIZE: usize = 39724; // BASE64 (THIS MAY CHANGE; DOUBLE CHECK)

    // FORMAT
    const FORMAT_ID: &'static str = "BASE32 (RFC4648) [A-Z][2-7][=]";
    const FORMAT_PUBLIC_KEY: &'static str = "HEXADECIMAL";
    const FORMAT_HASH: &'static str = "HEXADECIMAL";
    const FORMAT_SIGNATURE: &'static str = "BASE64 (STANDARD)";
    
    /// # New SPHINCS+ Certificate
    /// This function creates a SPHINCS+ Certificate and returns the `SphincsCertificate` and `Keypair` which can be serialized
    pub fn new() -> (Self,SphincsKeypair) {
        // Generate Public Key and Private Key
        let keypair: SphincsKeypair = SphincsKeypair::new();

        // Hash is 64 bytes (128 char) and id is 104 char.
        // Signature needs to be based off of id,keypair,hash
        let hash = SphincsCertificate::convert_to_hash(keypair.public_key.clone());


        let id: String = SphincsCertificate::encode_into_base32(&hex::decode(hash.clone()).unwrap());
        
        // Signature
        let appended_data: String = format!("{} {} {}",id,keypair.public_key,hash.clone());
        let signature = keypair.sign(&appended_data);

        return (
            SphincsCertificate {
                version: 0usize,
                id: id,
                pk: keypair.public_key.clone(),
                hash: hash,
                signature: signature.signature,
            },
        keypair
        )
    }
    /// # New SPHINCS+ Certificate (Proof-of-Work)
    /// This function performs **Proof-of-Work** to generate a certificate with a **specific id**. 
    /// ## Example Usage
    /// ```rust
    /// use selenite::certificate::SphincsCertificate;
    /// 
    /// fn main(){
    ///     let (cert,keypair) = SphincsCertificate::new_pow("WRLD");
    /// }
    /// ```
    pub fn new_pow(id_start: &str) -> (Self,SphincsKeypair) {
        // Convert To Uppercase and Take Len
        let name: String = id_start.to_ascii_uppercase();
        let name_length: usize = name.len();
        
        let mut attempts: usize = 0;
        let debug: bool = true;

        // Remove in future. Just here to prevent bugs.
        if name_length > 104usize {
            panic!("NameLengthTooLong")
        }
        
        loop {
            // Generate Public Key and Private Key
            let keypair: SphincsKeypair = SphincsKeypair::new();
            attempts += 1;
            if debug == true {
                println!("Attempt: {}",attempts);
            }

            // Hash is 64 bytes (128 char) and id is 104 char.
            // Signature needs to be based off of id,keypair,hash
            let hash = SphincsCertificate::convert_to_hash(keypair.public_key.clone());
            let id: String = SphincsCertificate::encode_into_base32(&hex::decode(hash.clone()).unwrap());
            
            if id.starts_with(&name) {
                // TODO: Make Sure Only Availble In Debug
                if debug == true {
                    println!("[X] Found A Certificate That Matches Your Request After {} Attempts",attempts);
                    println!();
                    println!("ID: {}",id);
                }
                let appended_data: String = format!("{} {} {}",id,keypair.public_key,hash.clone());
                let signature = keypair.sign(&appended_data);
                return (SphincsCertificate { version: 0usize, id: id, pk: keypair.public_key.clone(), hash: hash, signature: signature.signature,},keypair)
            }
        }
    }
    /// # Verify Signature
    /// This method verifies the attributes of the certificate with the signature. It is in the following format:
    /// 
    /// `{} {} {}` | `id, public key, hash`
    /// 
    /// ## Example Code
    /// ```rust
    /// use selenite::certificate::SphincsCertificate;
    /// 
    /// fn main() {
    ///     let (cert, keypair) = SphincsCertificate::new();
    ///     
    ///     assert_eq!(cert.verify_signature(),true);
    /// }
    /// ```
    fn verify_signature(&self) -> bool {
        let message: String = format!("{} {} {}",self.id,self.pk,self.hash);
        let is_valid: bool = Verify::new(KeypairAlgorithms::SPHINCS_PLUS, &self.pk, &self.signature, &message);
        return is_valid
    }
    fn verify_id(&self) -> bool {
        let hash = SphincsCertificate::convert_to_hash(self.pk.clone());
        let id_base32 = SphincsCertificate::encode_into_base32(&hex::decode(hash.clone()).unwrap());

        if self.id == id_base32 && self.hash == hash {
            return true
        }
        else {
            return false
        }
    }
    /// # Verify
    /// This method verifies the signature, hash, id, and public key.
    /// ## Example Code
    /// ```
    /// use selenite::certificate::SphincsCertificate;
    /// 
    /// fn main() {
    ///     let (cert, keypair) = SphincsCertificate::new();
    /// 
    ///     let is_valid: bool = cert.verify();
    /// }
    /// ```
    pub fn verify(&self) -> bool {
        let id_bool = self.verify_id();
        let sig_bool = self.verify_signature();
        
        if id_bool == true && sig_bool == true {
            return true
        }
        else {
            return false
        }
    }
    pub fn serialize(&self) -> String {
        return serde_yaml::to_string(&self).unwrap();
    }
    pub fn deserialize(yaml: &str) -> Self {
        let result = serde_yaml::from_str(yaml).unwrap();
        return result
    }
    // Converts Public Key To Bytes and Hashes It Using 64 bytes Then Encodes In Hexadecimal
    fn convert_to_hash(pk: String) -> String {
        // Converts From Hex To Byte String
        let pk_decoded = hex::decode(pk).unwrap();

        // Generates Hash From Public Key (Byte String)
        let hash = blake2b(Self::BLAKE2B_DIGEST_SIZE, &[], &pk_decoded);
        let hash_bytes = hash.as_bytes();
        
        // Outputs Hash As Hex-Encoded String
        let hash_hex = hex::encode_upper(hash_bytes);
        return hash_hex
    }
    // encodes as upper hexadecimal, in ascii, as_bytes(). Outputs a `String`
    fn encode_into_base32(hash: &[u8]) -> String {
        let id: String = base32::encode(Alphabet::RFC4648 { padding: true },hash);
        return id
    }
    fn assert_length(&self) -> bool {
        if self.id.len() == SphincsCertificate::STRING_ID_SIZE && self.pk.len() == SphincsCertificate::STRING_PUBLIC_KEY_SIZE && self.hash.len() == SphincsCertificate::STRING_HASH_SIZE && self.signature.len() == SphincsCertificate::STRING_SIGNATURE_SIZE {
            return true
        }
        else {
            return false
        }
    }
}