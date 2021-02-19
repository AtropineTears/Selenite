// Encoding
use base32::{Alphabet};

// Use Base32 (RFC 4648) and make sure its padded
// RFC 4648 states that padding must be used unless the specification of the standard referring to the RFC explicitly states otherwise

/// ## SphincsCertificate
/// A `SphincsCertificate` is a struct that contains:
/// * The **id** which is encoded in **base32** with characters [A-Z] and [1-7] based on the public key. It uses the **RFC4648 Format**.
/// * The **Public Key** which is encoded in **upper hexadecimal** and is **64 bytes**.
#[derive(Debug)]
pub struct SphincsCertificate {
    id: String,
    pk: String,
}

impl SphincsCertificate {
    pub fn generate() {
        
    }
    pub fn generate_with_specific_id(id: &str) {

    }
    fn encode_into_base32(pk: String) -> String {
        let id = base32::encode(RFC4648Base32,pk.to_ascii().as_bytes());
        return id
    }
    // Need to make sure it converts from bytes to string
    fn decode_from_base32(b_32: String) -> String {
        let pk = base32::decode(RFC4648Base32,&b_32);
    }
}