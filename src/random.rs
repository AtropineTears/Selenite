/// # OsRandom
/// 
/// OsRandom allows you to get randomness from your computer's CSPRNG. This is a secure location of getting randmoness from
/// and works cross-platform.
/// 
/// ```
/// 
/// use selenite::random::OsRandom;
/// 
/// fn main() {
///     let randomness_32 = OsRandom::rand_32.expect("Failed To Get Randomness");
/// 
///     let randomness_64 = OsRandom::rand_64.expect("Failed To Get Randomness");
/// 
///     let randomness_128 = OsRandom::rand_128.expect("Failed To Get Randomness");
/// }
/// ```
pub struct OsRandom;

impl OsRandom {
    pub fn rand_32() -> Result<[u8; 32], getrandom::Error> {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf)?;
        Ok(buf)
    }
    pub fn rand_48() -> Result<[u8; 48], getrandom::Error> {
        let mut buf = [0u8; 48];
        getrandom::getrandom(&mut buf)?;
        Ok(buf)
    }
    pub fn rand_64() -> Result<[u8; 64], getrandom::Error> {
        let mut buf = [0u8; 64];
        getrandom::getrandom(&mut buf)?;
        Ok(buf)
    }
    pub fn rand_128() -> Result<[u8; 128], getrandom::Error> {
        let mut buf = [0u8; 128];
        getrandom::getrandom(&mut buf)?;
        Ok(buf)
    }
    pub fn rand_256() -> Result<u8; 256>, getrandom::Error> {
        let mut buf = [0u8; 256];
        getrandom::getrandom(&mut buf)?;
        Ok(buf)
    }
}
