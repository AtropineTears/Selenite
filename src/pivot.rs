pub struct Pivot;

pub enum AddressTypes {
    CERT,
}

pub struct BlockLattice {
    CRS: String,
    
    mut NumberOfChains: u64,
    mut NumberOfValidators: u64,
}

pub struct CertificatePolicy {
    is_immutable: bool,
    secure_core_hashes: Vec<String>,
}

impl Pivot {
    pub fn new() -> BlockLattice {
        
    }
}