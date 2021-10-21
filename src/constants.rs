pub const MAX_BYTES_FOR_CERTIFICATE_FIELDS: usize = 256;

// Certificates
pub const SELENITE_VERSION: usize = 0usize;
pub const FINGERPRINT_BYTE_SIZE: usize = 80usize;
pub const BLAKE2B_DIGEST_SIZE_FOR_HASH: usize = 48usize;

// Hash Algorithm
pub const HASH_ALGORITHM: &str = "BLAKE2B_48";

pub const SIGNATURE_ALGORITHM_SPHINCS: &str = "SPHINCS+ (SHAKE256)";
pub const SIGNATURE_ALGORITHM_FALCON_512: &str = "FALCON512";
pub const SIGNATURE_ALGORITHM_FALCON_1024: &str = "FALCON1024";


// My Words
pub const SELENITE_DEVELOPER_ANNOUNCEMENT: &str = "Developed by @AtropineTears with the company SilentNightshade | Date: 10 Sept 2021";