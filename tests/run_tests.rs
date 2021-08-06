extern crate selenite;
use selenite::crypto::*;
use selenite::certificate::*;
use base64;

#[cfg(test)]
#[test]
fn create_falcon_keypair(){
    println!("========================================");
    println!("Falcon512");
    println!("========================================");
    println!("Generating FALCON512 Keypair...");
    let keypair = Falcon512Keypair::new();
    println!("[X] Generated Keypair");
    println!();
    println!("Serializing To YAML...");
    let yaml = keypair.export();
    println!("[X] Serializied");
    println!("Deserializing To YAML...");
    let keypair_from_yaml = Falcon512Keypair::import(&yaml);
    println!("[X] Deserializied");
    println!();
    println!("Generating FALCON512 Signature...");
    let signature = keypair_from_yaml.sign("FCA1509713AB6871E82CF33EB837032A9E3FA4BB4F5979A5A6FCD2ACD26B6A9015F580638CADCFFC81D94D4B3F4AD326F6F6FF67CD4A0B9DA1ECB74B3833647B");
    println!("[X] Generated Signature...");
    println!("Verifying FALCON512 Signature...");
    let is_verified = signature.verify();
    println!("[X] Verified Signature...");
    println!();
    println!("Message: {}",signature.message);
    println!();
    println!("Signature: {}",signature.signature);
    println!();
    println!("is_verified: {}",is_verified);
    println!();
}
#[test]
fn create_falcon1024_keypair(){
    let keypair = Falcon1024Keypair::new();
    let yaml = keypair.export();
    let keypair_from_yaml = Falcon1024Keypair::import(&yaml);

    let signature = keypair_from_yaml.sign("FCA1509713AB6871E82CF33EB837032A9E3FA4BB4F5979A5A6FCD2ACD26B6A9015F580638CADCFFC81D94D4B3F4AD326F6F6FF67CD4A0B9DA1ECB74B3833647B");
    let is_verified = signature.verify();

    println!("========================================");
    println!("Falcon1024");
    println!("========================================");
    println!("Message: {}",signature.message);
    println!();
    println!("Signature: {}",signature.signature);
    println!();
    println!("is_verified: {}",is_verified);
}
#[test]
fn create_sphincs_keypair(){
    println!();
    println!("========================================");
    println!("SPHINCS+ (SHAKE256s-robust)");
    println!("========================================");
    println!("Generating SPHINCS+ Keypair...");
    let keypair = SphincsKeypair::new();
    println!("[X] SPHINCS+ Keypair Generated");
    println!();
    println!("Serializing To YAML...");
    let yaml = keypair.export();
    println!("[X] Serialized To YAML");
    println!("Deserializing From YAML...");
    let keypair_from_yaml = SphincsKeypair::import(&yaml);
    println!("[X] Deserialized From YAML");
    println!();

    println!("Creating Signature of 512bit Hash (64 bytes)...");
    let signature = keypair_from_yaml.sign("FCA1509713AB6871E82CF33EB837032A9E3FA4BB4F5979A5A6FCD2ACD26B6A9015F580638CADCFFC81D94D4B3F4AD326F6F6FF67CD4A0B9DA1ECB74B3833647B");
    println!("[X] Signature Created");
    println!("Verifying Signature...");
    let is_verified = signature.verify();
    println!("[X] Signature Verified");
    println!();
    println!("Message: {}",signature.message);
    println!("Signature Length In Bytes: {}", signature.signature_as_bytes().len());
    println!("Signature Length In Base64: {}",signature.signature.len());
    println!("Verified: {}",is_verified);
    println!("End Test");
    println!();
}
#[test]
fn create_sphincs_certificate() {
    let (cert,_keypair) = SphincsCertificate::new();
    
}
#[test]
fn create_sphincs_certificate_with_id(){
    let (cert,_keypair) = SphincsCertificate::new();
    
    let sig_bool = cert.verify_signature();
    let id_bool = cert.verify_id();

    println!("Signature: {}",sig_bool);
    println!("ID: {}",id_bool);
}