pub trait Keypairs {
    /// ## Generate A New Keypair
    /// Create New Keypair From Respected Struct Being Called
    fn new() -> Self;
    /// ## Constructs A Keypair From Hexadecimal Representation
    /// Construct Keypair From Hexadecimal String or str. This will not generate a new keypair.
    fn construct<T: AsRef<str>>(pk: T, sk: T) -> Self;
    /// Return As Bytes
    fn as_bytes(&self) -> (Vec<u8>,Vec<u8>);
    /// Return Hexadecimal Public Key
    fn public_key(&self) -> &str;
    /// Return Hexadecimal Private Key
    fn secret_key(&self) -> &str;
    /// ## Keypair Signing
    /// Allows Signing of an Input Using The Keyholder's Secret Key and Returns The Struct Signature.
    fn sign(&self,input: String) -> Signature;
}
pub trait Signatures {
    fn verify(&self) -> bool;
}