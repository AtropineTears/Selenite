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
