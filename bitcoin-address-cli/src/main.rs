use clap::App;

use bitcoin_address::{hex::ToHex, Address, Format, KeyPair, Network};

fn main() {
    let matches = App::new("bitcoin-address")
        .version("1.0")
        .about("Generates P2PKH or P2SH bitcoin address from a given private key")
        .author("Bogdan A.")
        .args_from_usage(
            "<PRIVATE_KEY>          'Sets required bitcoin private key'
            -v, --verbose           'Uses verbose output'",
        )
        .get_matches();

    let private_key = matches.value_of("PRIVATE_KEY").unwrap();

    if matches.is_present("verbose") {
        compute_p2pkh_address(private_key, true);
    } else {
        compute_p2pkh_address(private_key, false);
    }
}

fn compute_p2pkh_address(secret: &str, verbose: bool) {
    let kp = match KeyPair::from_secret_key_str(secret) {
        Ok(kp) => kp,
        Err(_) => panic!("Invalid or unsupported secret key"), // glob for simplicity
    };

    if verbose {
        println!(
            "Secret key: {} {}",
            secret,
            if kp.compressed() {
                "(compressed)"
            } else {
                "(uncompressed)"
            }
        );
    }

    let pk = if kp.compressed() {
        kp.public().serialize().to_vec()
    } else {
        kp.public().serialize_uncompressed().to_vec()
    };

    if verbose {
        println!(
            "Public key (P2PKH): {} {}",
            pk.to_hex(),
            if kp.compressed() {
                "(compressed)"
            } else {
                "(uncompressed)"
            }
        )
    }

    let addr = match Address::from_public_key(&pk, Network::Mainnet, Format::P2PKH) {
        Ok(addr) => addr,
        Err(_) => panic!("There is an error deriving public key"), // glob for simplicity
    };

    println!(
        "{}",
        if verbose {
            format!("Bitcoin address: {}", addr)
        } else {
            addr.to_string()
        }
    );
}
