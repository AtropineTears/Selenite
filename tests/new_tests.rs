#[cfg(test)]
mod tests {
    use selenite::certificate::SeleniteCertificate;
    use super::*;
    use selenite::certificate::*;
    #[test]
    fn new_cert(){
        let cert = SeleniteCertificate::new(
        String::from("Subject Name"),
        CertificateType::INDIVIDUAL,
        Some(String::from("Username")),
        vec![KeyUsage::CODE_SIGNING,KeyUsage::DOCUMENT_SIGNING,KeyUsage::REVOCATION],
        Some(String::from("Email Address")),
        Some(String::from("Phone Number")),
        Some(String::from("Address")),
        Some(String::from("Backup Email")),
        Some(String::from("Backup Phone Number")),
        Some(String::from("Description")),
        Some(String::from("Website")),
        Some(String::from("@Github")),
        Some(String::from("@Reddit")),
        Some(String::from("@Twitter")),
        Some(String::from("@Keybase")),
        Some(String::from("Bitcoin Address (BTC)")),
        Some(String::from("Ethereum Address (ETH)")),
        Some(String::from("Monero Address (XMR)")),
        Some(String::from("Zcash Address (ZEC)")),
        Some(String::from("PGP Key")),
        Some(String::from("Onion Website")),
        Some(String::from("Backup PGP Key")),
        Some(0usize), // Last_Bitcoin_Block_Height,
        Some(String::from("Last Bitcoin Block Hash")),
        );
    }
}