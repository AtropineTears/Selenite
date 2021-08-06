# Selenite

![Crates.io](https://img.shields.io/crates/v/selenite?style=flat-square)
[![Build Status](https://travis-ci.org/0xAtropine/Selenite.svg?branch=master)](https://travis-ci.org/0xAtropine/Selenite)
![Crates.io](https://img.shields.io/crates/l/Selenite?style=flat-square)

An experimental rust crate for **Post-Quantum Code-Signing Certificates**.

All Digital Signatures are **Round Three NIST Post-Quantum Candidates** which are listed [here](https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions).

Please read the [documentation](https://docs.rs/selenite/0.2.1/selenite/crypto/index.html) for usage.

## Overview

**Digital Signatures:** 

* SPHINCS+

* FALCON512 | FALCON1024

* Dilithium (Unimplemented)

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

### Serialization

You can **Serialize** keypairs to YAML using serde-yaml.

```rust
fn serialize(){
    // Generates Keypair
    let keypair = SphincsKeypair::new();
    
    // Serializes Keypair To YAML
    let yaml = keypair.export();
    
    // Deserializes Keypair To Respected Struct
    let keypair_from_yaml = SphincsKeypair::import(&yaml);
}

```

```rust
fn serialize_signature(){
    // Generates Keypair
    let keypair = SphincsKeypair::new();

    // Generates Signature
    let signature = keypair.sign("Hello World!");

    // [BINCODE] Serialize To Bincode
    let bincode: Vec<u8> = signature.export_to_bincode();

    // [YAML] Serialize To YAML
    let yaml = signature.export();
}
```

## To-Do

* Add **[Dilithium](https://pq-crystals.org/dilithium/)**, another round three candidate

* Add better **Serialization**

* Add **Tests**

* **Refactor Code**

* ~~Remove **qteslapiii** which is now broken (but also was coded out awhile ago but not completely)~~

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
