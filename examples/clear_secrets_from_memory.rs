use selenite::crypto::*;

fn main(){
    // Set Keypair To Mutable
    let mut keypair = BLSKeypair::new();

    // Erase From Memory By Overwriting With Zeroes
    keypair.zeroize();
}