# Selenite

An experimental rust crate for **Post-Quantum Code-Signing Certificates**. Please read the documentation for usage.

![Selenite](https://www.earthboundtrading.com/media/catalog/product/cache/1/image/x669/17f82f742ffe127f42dca9de82fb58b1/6/0/60420-selenite20cmtowernobase-421-hero.jpg)

## Example Usage

```rust
use selenite::crypto::*;

fn main() {
    // Generates The Respected Keypair
    let keypair = SphincsKeypair::new();

    // Signs The Message as a UTF-8 Encoded String
    let mut sig = keypair.sign("message_to_sign");

    // Returns a boolean representing whether the signature is valid
    let is_verified = sig.verify();
}
```

## License

Licensed under either of

* Apache License, Version 2.0

* MIT license

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
