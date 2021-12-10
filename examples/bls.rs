use selenite::crypto::*;

fn main(){
    let keypair = BLSKeypair::new();
    let sig = keypair.sign("Lets sign this message :)");
}