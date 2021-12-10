// TODO
// - Test difference between blake2-rfc and blake2

// The Structure
// Basic Idea of Generation: PK (Hex) --> [Blake2b] Hash (Hex) --> ID (BASE32) | Sign with Private Key


// Recomendations
// It is recomended that you use SPHINCS+ for code-signing. It is highly secure with good security assumptions but is slow to verify.
// Falcon1024 should be used for everything else like signing other people certificates

// Encoding
use base32::{Alphabet,encode,decode};

// Hashing
use blake2_rfc::blake2b::{Blake2b,blake2b};

// Crypto
use crate::constants::*;
use crate::crypto::*;

// Serialization
use serde::{Serialize, Deserialize};

// Time
use chrono::prelude::*;
use std::time::{SystemTime, UNIX_EPOCH};

// URL Parsing
use url::{Url, ParseError};

use log;

use std::fmt::*;



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

// Types of Uses:
// 1. Code Signing (Binaries)
// 2. Document Signing (Text,Emails,Messages)

#[derive(Serialize,Deserialize,Debug,Clone,PartialEq,PartialOrd,Hash)]
pub enum KeyUsage {
    CODE_SIGNING,
    DOCUMENT_SIGNING,
    REVOCATION,
}

pub enum CertificateErrors {
    InvalidExpirationDate,
}

#[derive(Serialize,Deserialize,Debug,Clone,PartialEq,PartialOrd,Hash)]
pub enum CertificateType {
    INDIVIDUAL,
    ORGANIZATION,
}

/// # String Formats
/// Used for Error-Checking and also used for quick access to the format.
pub enum StringFormats {
    BASE32,
    BASE64,
    HEXADECIMAL,
}

/// ## SeleniteCertificate
/// A `SeleniteCertificate` is a struct that contains:
/// * The `version` states what Selenite version the certificate uses
/// * The `description` is what is displayed to those who view your certificate. (Optional)
/// * The `fingerprint` which is encoded in **base32** with characters [A-Z] and [1-7] based on the hash. It uses the **RFC4648 Format**.
/// * The `key_id` is a 6 byte hash of the public key and in hexadecimal
/// * The `contact_email` is the primary email associated with the account
/// * The `contact_address` is your address
/// * The `contact_phone_number` is the primary phone number for contact
/// * The `contact_backup_email` is the backup email address if the primary is not found. (Optional)
/// * The `contact_backup_phone_number` is the backup phone number
/// ## Social Media Fields
/// * The `twitter` field is for your twitter handle
/// * The `keybase` field is your keybase account URL
/// * The `website` field is your website
/// 
/// ## Subject Information
/// * The `subject_type` is the type of certificate between Individual, Company, and Other.
/// * The `subject_name` is the name of the certificate holder
/// * The `subject_username` is the username of the certificate holder
/// 
/// * The `certificate_type` is the type of certificate represented with a u8. There are 255 options.
/// 
/// * The `pk` (public key) which is encoded in **upper hexadecimal** and is **64 bytes**.
/// * The `hash` is a 64 byte hash using blake2b in hexadecimal. It is a hash of the public key (in bytes).
/// * The `signature` is a signature of the id,pk, and hash combined together.
/// 
/// The id is similar to the Serial Number
/// 
/// The Certificate should be used to **sign binaries** as it is **slow but very secure (assuming there are no vulnerabilties or side channel attacks)**.
#[derive(Serialize,Deserialize,Debug,Clone,PartialEq,PartialOrd,Hash)]
pub struct SeleniteCertificate {
    version: usize, // 0
    fingerprint: String, // Unique Fingerprint (104 bytes) encoded in Base32 that is representative of your `Hash(Public Key)`
    // The `description` which is shown to those who look at your certificate
    
    
    description: Option<String>, // Displayed to User
    key_id: String, // 6 Bytes
    // Contact Email,Address,Phone Number( Optional)
    contact_email: Option<String>,
    contact_address: Option<String>,
    contact_phone_number: Option<String>,
    
    // Backups (Optional)
    contact_backup_email: Option<String>,
    contact_backup_phone_number: Option<String>,

    // Social Media and Website (Optional)
    twitter_unverified: Option<String>,
    reddit_unverified: Option<String>,
    keybase_unverified: Option<String>,
    website_unverified: Option<String>,
    github_unverified: Option<String>,

    // onion
    onion_website_unverified: Option<String>,

    // PGP
    pgp_key_unverified: Option<String>,
    backup_pgp_key_unverified: Option<String>,

    // Blockchain
    btc_address_unverified: Option<String>,
    eth_address_unverified: Option<String>,
    xmr_address_unverified: Option<String>,
    zec_address_unverified: Option<String>,

    // Subject Information
        // INDIVIDUAL,ORGANIZATION,OTHER
    subject_type: CertificateType,
    subject_name: String,
    subject_username: Option<String>,

    key_usage: Vec<KeyUsage>,

    // Types of Certificates (0-255)
    certificate_type: u8, // 0 is wildcard. Not determined

    // Important Information
    pk: String, // 64 bytes
    blake2b_hash: String, // 64 bytes Blake2b

    // Timestamp (ISO8601)
    generation_timestamp: DateTime<Utc>,

    last_bitcoin_block_height: Option<usize>,
    last_bitcoin_block_hash: Option<String>,
    //expiration_date: DateTime<Utc>,

    selenite_developer_announcement: String,

    // Algorithms
    hash_algorithm: String,
    signature_algorithm: String,
    // Signature of All Fields
    signature: String,
}

// SeleniteCertificate Signature Algorithms
// "SPHINCS+ (SHAKE256)"

// SeleniteCertificate Hash Algorithm
// "BLAKE2B_48"

impl SeleniteCertificate {
    // 0 means test version where certificates can break between versions
    const VERSION: usize = 0;
    const BLAKE2B_DIGEST_SIZE: usize = 48;
    
    // STRING SIZES (in bytes)
    const STRING_ID_SIZE: usize = 80; // BASE32
    const STRING_PUBLIC_KEY_SIZE: usize = 128; // HEXADECIMAL
    const STRING_HASH_SIZE: usize = 96; // HEXADECIMAL
    const STRING_SIGNATURE_SIZE: usize = 39724; // BASE64 (THIS MAY CHANGE; DOUBLE CHECK)

    // FORMAT
    const FORMAT_FINGERPRINT: &'static str = "BASE32 (RFC4648) [A-Z][2-7][=]";
    const FORMAT_PUBLIC_KEY: &'static str = "HEXADECIMAL";
    const FORMAT_HASH: &'static str = "HEXADECIMAL";
    const FORMAT_SIGNATURE: &'static str = "BASE64 (STANDARD)";
    
    /// # New SPHINCS+ Certificate
    /// This function creates a SPHINCS+ Certificate and returns the `SeleniteCertificate` and `Keypair` which can be serialized
    pub fn new(subject_name: String, subject_type: CertificateType, subject_username: Option<String>, key_usage: Vec<KeyUsage>, contact_email: Option<String>,contact_phone_number: Option<String>, contact_address: Option<String>,contact_backup_email: Option<String>,contact_backup_phone_number: Option<String>, description: Option<String>,website_unverified: Option<String>,github_unverified: Option<String>,reddit_unverified: Option<String>,twitter_unverified: Option<String>,keybase_unverified: Option<String>,btc_address_unverified: Option<String>,eth_address_unverified: Option<String>,xmr_address_unverified: Option<String>,zec_address_unverified: Option<String>,pgp_key_unverified: Option<String>,onion_website_unverified: Option<String>,backup_pgp_key_unverified: Option<String>,last_bitcoin_block_height: Option<usize>,last_bitcoin_block_hash: Option<String>) -> (Self,SphincsKeypair) {
        let certificate_type: u8 = 0u8;

        // Optional
        /*
        let btc_address = None;
        let contact_address = None;
        let contact_backup_email = None;
        let contact_backup_phone_number = None;
        let contact_email = None;
        let contact_phone_number = None;
        let description = None;
        let eth_address = None;
        let github = None;
        let keybase = None;
        let reddit = None;
        let twitter = None;
        let website = None;
        let xmr_address = None;
        */
        
        // Generate Public Key and Private Key
        let keypair: SphincsKeypair = SphincsKeypair::new();

        // Hash is 48 bytes (96 char) and fingerprint is 80 char.
        let blake2b_hash = SeleniteCertificate::convert_to_hash(keypair.public_key.clone());

        // Fingerprint is 80 bytes (encoded in Base32)
        let fingerprint: String = SeleniteCertificate::encode_into_base32(&hex::decode(blake2b_hash.clone()).unwrap());

        let key_id = SeleniteCertificate::generate_key_id_from_pk(keypair.public_key.clone());

        let generation_timestamp = SeleniteCertificate::get_utc_time();
        
        // Signature
        // 34 attributes
        let appended_data: String = format!(
        "
        {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {:?} {} {} {} {} {} {} {} {} {} {} {} {} {} {}
        ",
        crate::constants::SELENITE_VERSION,
        backup_pgp_key_unverified.clone().unwrap_or("No Backup PGP Key".to_string()),
        btc_address_unverified.clone().unwrap_or("No Bitcoin Address".to_string()),
        blake2b_hash,
        certificate_type,
        contact_address.clone().unwrap_or("No Contact Address".to_string()),
        contact_backup_email.clone().unwrap_or("No Backup Email".to_string()),
        contact_backup_phone_number.clone().unwrap_or("No Backup Phone".to_string()),
        contact_email.clone().unwrap_or("No Contact Email".to_string()),
        contact_phone_number.clone().unwrap_or("No Contact Phone Number".to_string()),
        description.clone().unwrap_or("No Description Available".to_string()),
        eth_address_unverified.clone().unwrap_or("No Ethereum Address".to_string()),
        fingerprint,
        generation_timestamp,
        github_unverified.clone().unwrap_or("No GitHub Account".to_string()),
        onion_website_unverified.clone().unwrap_or("No .onion Website".to_string()),
        crate::constants::HASH_ALGORITHM,
        key_id,
        keybase_unverified.clone().unwrap_or("No Keybase Account".to_string()),
        key_usage,
        last_bitcoin_block_height.unwrap_or(0usize),
        last_bitcoin_block_hash.clone().unwrap_or("No Last Bitcoin Block Hash".to_string()),
        keypair.public_key.clone(),
        pgp_key_unverified.clone().unwrap_or("No PGP Key".to_string()),
        reddit_unverified.clone().unwrap_or("No Reddit Account".to_string()),
        crate::constants::SELENITE_DEVELOPER_ANNOUNCEMENT,
        crate::constants::SIGNATURE_ALGORITHM_SPHINCS,
        subject_name,
        subject_type,
        subject_username.clone().unwrap_or("No Username Provided".to_string()),
        twitter_unverified.clone().unwrap_or("No Twitter handle".to_string()),
        xmr_address_unverified.clone().unwrap_or("No XMR Address".to_string()),
        website_unverified.clone().unwrap_or("No Website".to_string()),
        zec_address_unverified.clone().unwrap_or("No ZEC Address".to_string())
        );
        let signature = &keypair.sign(&appended_data).signature;

        // Get Current Time
        let time = SeleniteCertificate::get_utc_time();

        return (
            SeleniteCertificate {
                version: crate::constants::SELENITE_VERSION,
                backup_pgp_key_unverified: backup_pgp_key_unverified,
                btc_address_unverified: btc_address_unverified,
                blake2b_hash: blake2b_hash,

                certificate_type: certificate_type,
                contact_address: contact_address,
                contact_backup_email: contact_backup_email,
                contact_backup_phone_number: contact_backup_phone_number,
                contact_email: contact_email,
                contact_phone_number: contact_phone_number,
                description: description,
                eth_address_unverified: eth_address_unverified,
                //expiration_date: Utc.ymd(2021, 7, 8).and_hms(9, 10, 11),
                fingerprint: fingerprint,
                generation_timestamp: generation_timestamp,
                github_unverified: github_unverified,
                onion_website_unverified: onion_website_unverified,
                hash_algorithm: crate::constants::HASH_ALGORITHM.to_string(),
                key_id: key_id,
                keybase_unverified: keybase_unverified,
                key_usage: key_usage,
                last_bitcoin_block_height: last_bitcoin_block_height,
                last_bitcoin_block_hash: last_bitcoin_block_hash,
                pk: keypair.public_key.clone(),
                pgp_key_unverified: pgp_key_unverified,
                reddit_unverified: reddit_unverified,
                selenite_developer_announcement: crate::constants::SELENITE_DEVELOPER_ANNOUNCEMENT.to_string(),
                signature_algorithm: crate::constants::SIGNATURE_ALGORITHM_SPHINCS.to_string(),
                subject_name: subject_name,
                subject_type: subject_type,
                subject_username: subject_username,
                twitter_unverified: twitter_unverified,
                xmr_address_unverified: xmr_address_unverified,
                website_unverified: website_unverified,
                zec_address_unverified: zec_address_unverified,

                signature: signature.to_string(),
            },
        keypair
        )
    }
    pub fn new_input(&self){
        // Create String
        let mut input = String::new();

        println!("Would You Like To Generate a Certificate [y/N]");
        //io::stdin().read_line(&mut number).expect("Failed to read input");
    }
    /// # New SPHINCS+ Certificate (Proof-of-Work)
    /// This function performs **Proof-of-Work** to generate a certificate with a **specific id**. 
    /// ## Example Usage
    /// ```rust
    /// use selenite::certificate::SeleniteCertificate;
    /// 
    /// fn main(){
    ///     let (cert,keypair) = SeleniteCertificate::new_pow("WRLD");
    /// }
    /// ```
    /*
    pub fn new_pow(id_start: &str,turn_on_debugging: bool) -> (Self,SphincsKeypair) {
        // Convert To Uppercase and Take Len
        let name: String = id_start.to_ascii_uppercase();
        let name_length: usize = name.len();
        
        let mut attempts: usize = 0;

        // Remove in future. Just here to prevent bugs.
        if name_length > 104usize {
            panic!("NameLengthTooLong")
        }
        
        loop {
            // Generate Public Key and Private Key
            let keypair: SphincsKeypair = SphincsKeypair::new();
            attempts += 1;
            if turn_on_debugging == true {
                println!("Attempt: {}",attempts);
            }

            // Hash is 64 bytes (128 char) and id is 104 char.
            // Signature needs to be based off of id,keypair,hash
            let blake2b_hash = SeleniteCertificate::convert_to_hash(keypair.public_key.clone());
            let fingerprint: String = SeleniteCertificate::encode_into_base32(&hex::decode(hash.clone()).unwrap());
            
            if id.starts_with(&name) {
                // TODO: Make Sure Only Availble In Debug
                if turn_on_debugging == true {
                    println!("[X] Found A Certificate That Matches Your Request After {} Attempts",attempts);
                    println!();
                    println!("ID: {}",id);
                }
                //let appended_data: String = format!("{} {} {}",id,keypair.public_key,hash.clone());
                //let signature = keypair.sign(&appended_data);
                return (SeleniteCertificate { version: 0usize, fingerprint: fingerprint, pk: keypair.public_key.clone(), blake2b_hash: blake2b_hash, signature: signature.signature,},keypair)
            }
        }
    }
    */
    /// # Verify Signature
    /// This method verifies the attributes of the certificate with the signature. It is in the following format:
    /// 
    /// `{} {} {}` | `id, public key, hash`
    /// 
    /// ## Example Code
    /// ```rust
    /// use selenite::certificate::SeleniteCertificate;
    /// 
    /// fn main() {
    ///     let (cert, keypair) = SeleniteCertificate::new();
    ///     
    ///     assert_eq!(cert.verify_signature(),true);
    /// }
    /// ```
    /*
    fn verify_signature(&self) -> bool {
        let message: String = format!("{} {} {}",self.fingerprint,self.pk,self.);
        //let is_valid: bool = Verify::new(KeypairAlgorithms::SPHINCS_PLUS, &self.pk, &self.signature, &message);
        return is_valid
    }
    */
    fn verify_fingerprint(&self) -> bool {
        let blake2b_hash = SeleniteCertificate::convert_to_hash(self.pk.clone());
        let fingerprint_base32 = SeleniteCertificate::encode_into_base32(&hex::decode(blake2b_hash.clone()).unwrap());

        // Checks
        // 1. Fingerprint is equal to self.fingerprint
        // 2. Hash is equal to self.hash
        // 3. Fingerprint is 80 bytes (check)
        if self.fingerprint == fingerprint_base32 && self.blake2b_hash == blake2b_hash && self.fingerprint.as_bytes().len() == 80usize {
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
    /// use selenite::certificate::SeleniteCertificate;
    /// 
    /// fn main() {
    ///     let (cert, keypair) = SeleniteCertificate::new();
    /// 
    ///     let is_valid: bool = cert.verify();
    /// }
    /// ```
    pub fn verify(&self) -> bool {
        let id_bool = self.verify_fingerprint();
        //let sig_bool = self.verify_signature();
        
        if id_bool == true {
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
        let fingerprint: String = base32::encode(Alphabet::RFC4648 { padding: true },hash);
        return fingerprint
    }
    fn assert_length(&self) -> bool {
        if self.fingerprint.len() == SeleniteCertificate::STRING_ID_SIZE && self.pk.len() == SeleniteCertificate::STRING_PUBLIC_KEY_SIZE && self.blake2b_hash.len() == SeleniteCertificate::STRING_HASH_SIZE && self.signature.len() == SeleniteCertificate::STRING_SIGNATURE_SIZE {
            return true
        }
        else {
            return false
        }
    }
    pub fn get_utc_time() -> DateTime<Utc>{
        return Utc::now()
    }
    fn format_date(year: i32, month: u32, day: u32) -> DateTime<Utc>{
        return Utc.ymd(year, month, day).and_hms(9, 10, 11);
    }
    /*
    fn security_check_if_certificate_valid(&self) -> Result<bool,CertificateErrors> {
        if self.generation_timestamp > self.expiration_date {
            println!("[Error] Expiration Date");
            return Ok(true)
        }
        else if self.generation_timestamp < self.expiration_date {
            println!("The timestamp is less than the expiration date")
            return Err(CertificateErrors::InvalidExpirationDate)
        }
        else if self.generation_timestamp == self.expiration_date {
            println!("[ERROR] Generation Timestamp is equal to Expirary Date. This is NOT a Valid Certificate and should be disposed of.")
            return Err(CertificateErrors::InvalidExpirationDate)
        }
    }
    */
    pub fn security_get_duration_since_from_generation(&self) -> std::time::Duration {
        let sys_time: SystemTime = self.generation_timestamp.into();
        println!("[DEBUG] This function should debug for maximum protection");
        return SystemTime::now().duration_since(sys_time).expect("Failed To Get Duration Since.")
    }
    pub fn generate_key_id_from_pk(pk: String) -> String {
        // Key ID (6 bytes)
        let mut context = Blake2b::new(6);
    
        context.update(&hex::decode(pk.as_bytes()).expect("Failed To Decode Hexadecimal"));

        return hex::encode(context.finalize().as_bytes());
    }
    /*
    pub fn verify_certificate_fields(&self){
        if self.version > 0usize {
            log::debug!("Certificate-Version: This version is new and not yet implemented.")
        }
        else if self.version == 0usize {
            log::debug!("Certificate-Version: Version 0")
        }
        else {
            log::error!("Certificate Version is not found")
        }
        
        // Asserts len(Fingerprint) = 80 bytes
        assert_eq!(self.fingerprint.chars().count(),80usize);
        // Asserts len(hash) = 96 bytes
        assert_eq!(self.blake2b_hash.chars().count(),96usize);

        if 
        // description (256 bytes)
        // email (max: 254 bytes)
        // phone (max: 15) | Set to 20 to allow other chars
        // github (max: 64?)
        
        &self.description.unwrap().chars().count() > 256usize || 
        self.contact_address.unwrap().chars().count() > 256usize || 
        self.contact_backup_email.unwrap().chars().count() > 256usize ||
        self.contact_backup_phone_number.unwrap().chars().count() > 30usize ||
        self.contact_email.unwrap().chars().count() > 256usize ||
        self.contact_phone_number.unwrap().chars().count() > 30usize ||
        //self.expiration_date
        self.fingerprint.chars().count() > 104usize ||
        //self.generation_timestamp
        self.github.unwrap().chars().count() > 256usize ||
        self.blake2b_hash.chars().count() > 128usize ||
        self.hash_algorithm.chars().count() > 256usize ||
        self.key_id.chars().count() > 12usize ||
        self.keybase.unwrap().chars().count() > 256usize ||
        //self.last_bitcoin_block.unwrap()
        self.last_bitcoin_block_hash.unwrap().chars().count() > 128usize ||
        //self.last_ethereum_block.unwrap()
        self.last_bitcoin_block_hash.unwrap().chars().count() > 128usize ||
        self.pk.chars().count() > 128usize ||
        self.reddit.unwrap().chars().count() > 256usize ||
        self.signature.chars().count() > 39724usize ||
        self.signature_algorithm.chars().count() > 256usize ||
        self.subject_name.chars().count() > 256usize ||
        //self.subject_type
        self.subject_username.unwrap().chars().count() > 256usize ||
        // Twitter: 15 char limit. Add 1 char for @
        self.twitter.unwrap().chars().count() > 256usize ||
        //self.version > 0usize ||
        self.website.unwrap().chars().count() > 256usize ||
        self.btc_address.unwrap().chars().count() > 256usize ||
        self.xmr_address.unwrap().chars().count() > 256usize
        {
            println!("Certificate is Invalid.")
        }
    
    }
    */
}

// Display For KeyUsage
impl std::fmt::Display for KeyUsage {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            KeyUsage::CODE_SIGNING => write!(f, "CODE_SIGNING"),
            KeyUsage::DOCUMENT_SIGNING => write!(f, "DOCUMENT_SIGNING"),
            KeyUsage::REVOCATION => write!(f, "REVOCATION")
        }
    }
}

// Display For CertificateType
impl std::fmt::Display for CertificateType {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            CertificateType::INDIVIDUAL => write!(f, "INDIVIDUAL"),
            CertificateType::ORGANIZATION => write!(f, "ORGANIZATION"),
        }
    }
}