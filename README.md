# Selenite

![Crates.io](https://img.shields.io/crates/v/selenite?style=flat-square)
[![Build Status](https://app.travis-ci.com/AtropineTears/Selenite.svg?branch=master)](https://app.travis-ci.com/AtropineTears/Selenite)
![Crates.io](https://img.shields.io/crates/l/Selenite?style=flat-square)

An experimental rust crate for **Post-Quantum Code-Signing Certificates**.

All Digital Signatures are **Round Three NIST Post-Quantum Candidates** which are listed [here](https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions).

Please read the [documentation](https://docs.rs/selenite/0.2.1/selenite/crypto/index.html) for usage.

## Overview

**Digital Signatures:** 

* SPHINCS+
* FALCON512 and FALCON1024
* ED25519**<sup>*</sup>**

\*: Not Post-Quantum Cryptography

## Example Usage

### SPHINCS+ (SHAKE256)

Read [SPHINCS+](https://sphincs.org/)

**SPHINCS+** is a Stateless Hash-Based Signature Scheme taking its cryptographic assumptions against Quantum Computers from cryptographic hash functions.

This Digital Signature implementation reaches a **Security Level of 5**, which is the most secure a signature can be, by using the hash function **SHAKE256** and setting other security parameters. However, SPHINCS+ has slow verification time compared to other choices.

* **SPHINCS+ Version:** sphincsshake256256srobust

* **Public Key Size:** 64 bytes 

* **Private Key Size:** 128 bytes

* **Signature Size:** 29,792 bytes

```rust
use selenite::crypto::*;

fn main() {
    // Generates The Respected Keypair
    let keypair = SphincsKeypair::new();

    // Signs The Message as a UTF-8 Encoded String
    let mut signature = keypair.sign("message_to_sign");

    // Returns a boolean representing whether the signature is valid or not
    let is_verified = signature.verify();
}
```
### FALCON512/FALCON1024

Read [FALCON](https://falcon-sign.info/)

FALCON is a lattice-based signature scheme whos underlying problem is based upon the short integer solution problem (SIS) over NTRU lattices, for which no efficient solving algorithm is currently known in the general case, even with the help of quantum computers. Falcon512 is similar in classical security assumptions to the security of RSA2048.

* **Public Key Size:** 897 bytes | 1793 bytes

* **Private Key Size:** 1281 bytes | 2305 bytes

* **Signature Size:** 660 bytes | 1280 bytes


```rust
use selenite::crypto::*;

fn main(){
    // Generates FALCON512 Keypair
    let keypair = Falcon512Keypair::new();
    
    // Generates FALCON1024 Keypair
    let keypair2 = Falcon1024Keypair::new();
    
    // Signs The Message as a UTF-8 Encoded String using the first keypair (FALCON512)
    let signature = keypair.sign("Message1");
    
    // Returns a boolean representing whether the signature is valid or not
    let is_verified = signature.verify();
}
```

### ED25519

ED25519 is an elliptic-curve based digital signature by DJB that has small public keys, private keys, and signatures.

It is not post-quantum secure but has been included in this library.

* **Public Key Size:** 32 bytes

* **Private Key Size:** 32 bytes

* **Signature Size:** 64 bytes


```rust
use selenite::crypto::*;

fn main(){
    // Generates ED25519 Keypair
    let keypair = ED25519::new();
    
  	// Signs Message
    let signature = keypair.sign("Message1");
    
    // Returns a boolean representing whether the signature is valid or not
    let is_verified = signature.verify();
}
```

### Serialization

You can **Serialize** keypairs to YAML using serde-yaml.

```rust
fn serialize(){
    // Generates Keypair
    let keypair = SphincsKeypair::new();
    
    // Serializes Keypair To YAML
    let yaml = keypair.serialize();
    
    // Deserializes Keypair To Respected Struct
    let keypair_from_yaml = SphincsKeypair::deserialize(&yaml);
}

```

```rust
fn serialize_signature(){
    // Generates Keypair
    let keypair = SphincsKeypair::new();

    // Generates Signature
    let signature = keypair.sign("Hello World!");

    // [BINCODE] Serialize To Bincode
    let bincode: Vec<u8> = signature.serialize_to_bincode();

    // [YAML] Serialize To YAML
    let yaml = signature.serialize();
}
```

### Randomness From CSPRNG

Selenite allows you to easily get secure randomness from your operating system.

```rust
use selenite::random::OsRandom;

fn main() {
    let randomness_32 = OsRandom::rand_32.expect("Failed To Get Randomness");

    let randomness_64 = OsRandom::rand_64.expect("Failed To Get Randomness");

    let randomness_128 = OsRandom::rand_128.expect("Failed To Get Randomness");
}
```

### Create SPHINCS+ Certificate

```rust
use selenite::crypto::SphincsKeypair;
use selenite::certificate::*;

fn main(){
    let (cert,keypair) = SeleniteCertificate::new(
        String::from("Subject Name"),
        CertificateType::INDIVIDUAL,
        Some(String::from("[Optional] Username")),
        vec![KeyUsage::CODE_SIGNING,KeyUsage::DOCUMENT_SIGNING,KeyUsage::REVOCATION],
        Some(String::from("[Optional] Email Address")),
        Some(String::from("[Optional] Phone Number")),
        Some(String::from("[Optional] Address")),
        Some(String::from("[Optional] Backup Email")),
        Some(String::from("[Optional] Backup Phone Number")),
        Some(String::from("[Optional] Description")),
        Some(String::from("[Optional] Website")),
        Some(String::from("[Optional] @Github")),
        Some(String::from("[Optional] @Reddit")),
        Some(String::from("[Optional] @Twitter")),
        Some(String::from("[Optional] @Keybase")),
        Some(String::from("[Optional] Bitcoin Address (BTC)")),
        Some(String::from("[Optional] Ethereum Address (ETH)")),
        Some(String::from("[Optional] Monero Address (XMR)")),
        Some(String::from("[Optional] Zcash Address (ZEC)")),
        Some(String::from("[Optional] PGP Key")),
        Some(String::from("[Optional] Onion Website")),
        Some(String::from("[Optional] Backup PGP Key")),
        Some(0usize), // (Optional) | Last_Bitcoin_Block_Height,
        Some(String::from("[Optional] Last Bitcoin Block Hash")),
        );
}
```

## To-Do

* Add **[Dilithium](https://pq-crystals.org/dilithium/)**, another round three candidate

* Add better **Serialization**

* Add **Tests**

* **Refactor Code**

## Resources

* [NIST Status Report](https://nvlpubs.nist.gov/nistpubs/ir/2020/NIST.IR.8309.pdf)

* [NIST Round Three Submissions](https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions)

* [PQClean](https://github.com/pqclean/pqclean/)

* [PQcrypto](https://github.com/rustpq/pqcrypto) | [Crate](https://crates.io/crates/pqcrypto)

## License

Licensed under either of

* Apache License, Version 2.0

* MIT license

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
