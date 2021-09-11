pub const MAX_BYTES_FOR_CERTIFICATE_FIELDS: usize = 256;

// Certificates
pub const SELENITE_VERSION: usize = 0usize;
pub const FINGERPRINT_BYTE_SIZE: usize = 80usize;
pub const BLAKE2B_DIGEST_SIZE_FOR_HASH: usize = 48usize;

pub const HASH_ALGORITHM: &str = "BLAKE2B_48";
pub const SIGNATURE_ALGORITHM: &str = "SPHINCS+ (SHAKE256)";

// My Words
pub const SELENITE_DEVELOPER_ANNOUNCEMENT: &str = "Developed by @AtropineTears with the company OpenNightshade | Date: 10 Sept 2021";