use secp256k1::{PublicKey, Secp256k1, SecretKey};

/// secp256k1-based bitcoin keypair
pub struct KeyPair {
    secret: SecretKey,
    public: PublicKey,
    compressed: bool, // both (un)compressed, same for simplicity
}

/// Keypair errors
#[derive(Debug, Fail)]
pub enum KeyPairError {
    #[fail(display = "invalid secret")]
    InvalidSecret,
    #[fail(display = "invalid secret length")]
    InvalidSecretLength,
}

impl KeyPair {
    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    pub fn compressed(&self) -> bool {
        self.compressed
    }

    pub fn from_secret_key_str(secret: &str) -> Result<KeyPair, KeyPairError> {
        let s = bs58::decode(secret)
            .into_vec()
            .map_err(|_| KeyPairError::InvalidSecret)?;

        let compressed = match s.len() {
            37 => false,
            38 => true,
            _ => return Err(KeyPairError::InvalidSecretLength),
        };

        let engine = Secp256k1::new();
        let secret = SecretKey::from_slice(&s[1..33]).expect("32 bytes, within curve order");
        let public = PublicKey::from_secret_key(&engine, &secret);

        let keypair = KeyPair {
            secret,
            public,
            compressed,
        };

        Ok(keypair)
    }
}

#[cfg(test)]
mod tests {
    use super::KeyPair;
    use crate::{Address, Format, Network};

    // keys/addresses to test
    const SECRET_0: &'static str = "5KSCKP8NUyBZPCCQusxRwgmz9sfvJQEgbGukmmHepWw5Bzp95mu";
    const SECRET_1: &'static str = "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj";
    const SECRET_2: &'static str = "5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3";

    const SECRET_1C: &'static str = "Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw";
    const SECRET_2C: &'static str = "L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g";

    const ADDRESS_0: &'static str = "16meyfSoQV6twkAAxPe51RtMVz7PGRmWna";
    const ADDRESS_1: &'static str = "1QFqqMUD55ZV3PJEJZtaKCsQmjLT6JkjvJ";
    const ADDRESS_2: &'static str = "1F5y5E5FMc5YzdJtB9hLaUe43GDxEKXENJ";

    const ADDRESS_1C: &'static str = "1NoJrossxPBKfCHuJXT4HadJrXRE9Fxiqs";
    const ADDRESS_2C: &'static str = "1CRj2HyM1CXWzHAXLQtiGLyggNT9WQqsDs";

    fn test_address(secret: &'static str, address: &'static str) -> bool {
        let kp = KeyPair::from_secret_key_str(secret).unwrap();

        let pk = if kp.compressed() {
            kp.public().serialize().to_vec()
        } else {
            kp.public().serialize_uncompressed().to_vec()
        };

        let addr = Address::from_public_key(&pk, Network::Mainnet, Format::P2PKH).unwrap();

        addr == address.into()
    }

    #[test]
    fn test_keypair_address() {
        assert!(test_address(SECRET_0, ADDRESS_0));
        assert!(test_address(SECRET_1, ADDRESS_1));
        assert!(test_address(SECRET_2, ADDRESS_2));
        assert!(test_address(SECRET_1C, ADDRESS_1C));
        assert!(test_address(SECRET_2C, ADDRESS_2C));
    }
}
