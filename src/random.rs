pub fn OSRandom;

impl OSRandom {
    fn rand_32() -> Result<[u8; 32], getrandom::Error> {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf)?;
        Ok(buf)
    }
    fn rand_48() -> Result<[u8; 48], getrandom::Error> {
        let mut buf = [0u8; 48];
        getrandom::getrandom(&mut buf)?;
        Ok(buf)
    }
    fn rand_64() -> Result<[u8; 64], getrandom::Error> {
        let mut buf = [0u8; 64];
        getrandom::getrandom(&mut buf)?;
        Ok(buf)
    }
    fn rand_128() -> Result<[u8; 128], getrandom::Error> {
        let mut buf = [0u8; 128];
        getrandom::getrandom(&mut buf)?;
        Ok(buf)
    }
}