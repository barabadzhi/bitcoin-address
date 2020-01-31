use std::{fmt, str};

use bitcoin_hashes::{hash160, sha256d, Hash};

use crate::{Hash160, Hash32, Network};

/// Bitcoin address format
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Format {
	/// Pay to PubKey Hash
	/// Starts with the number 1
	/// https://bitcoin.org/en/glossary/p2pkh-address
	P2PKH,
	/// Pay to Script Hash
	/// Starts with the number 3
	/// https://bitcoin.org/en/glossary/p2sh-address
	P2SH,
}

/// Bitcoin address
#[derive(Debug, PartialEq)]
pub struct Address {
	pub format: Format,
	pub network: Network,
	pub hash: Hash160,
}

/// Bitcoin address parsing errors
#[derive(Debug, Fail)]
pub enum AddressError {
	#[fail(display = "invalid address")]
	InvalidAddress,
	#[fail(display = "invalid checksum")]
	InvalidChecksum,
}

impl Address {
	pub fn from_slice(data: &[u8]) -> Result<Self, AddressError> {
		if data.len() != 25 {
			return Err(AddressError::InvalidAddress);
		}

		let cs = checksum(&data[0..21]);
		if data[21..] != *cs {
			return Err(AddressError::InvalidChecksum);
		}

		let (network, format) = match data[0] {
			111 => (Network::Testnet, Format::P2PKH),
			196 => (Network::Testnet, Format::P2SH),
			0 => (Network::Mainnet, Format::P2PKH),
			5 => (Network::Mainnet, Format::P2SH),
			_ => return Err(AddressError::InvalidAddress),
		};

		let mut hash = Hash160::default();
		hash.copy_from_slice(&data[1..21]);

		let address = Address {
			format,
			network,
			hash,
		};

		Ok(address)
	}

	fn to_array(&self) -> [u8; 25] {
		let mut result = [0u8; 25];

		result[0] = match (self.network, self.format) {
			(Network::Testnet, Format::P2PKH) => 111,
			(Network::Testnet, Format::P2SH) => 196,
			(Network::Mainnet, Format::P2PKH) => 0,
			(Network::Mainnet, Format::P2SH) => 5,
		};

		result[1..21].copy_from_slice(&*self.hash);

		let cs = checksum(&result[0..21]);
		result[21..25].copy_from_slice(&*cs);

		result
	}

	pub fn from_public_key(
		public_key: &[u8],
		network: Network,
		format: Format,
	) -> Result<Self, AddressError> {
		let mut pk_hash: [u8; 20] = [0u8; 20];
		pk_hash.copy_from_slice(&hash160::Hash::hash(public_key));

		let mut result = [0u8; 25];

		result[0] = match (network, format) {
			(Network::Testnet, Format::P2PKH) => 111,
			(Network::Testnet, Format::P2SH) => 196,
			(Network::Mainnet, Format::P2PKH) => 0,
			(Network::Mainnet, Format::P2SH) => 5,
		};

		result[1..21].copy_from_slice(&pk_hash);

		let cs = checksum(&result[0..21]);
		result[21..25].copy_from_slice(&*cs);

		Address::from_slice(&result)
	}
}

impl fmt::Display for Address {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		bs58::encode(self.to_array()).into_string().fmt(f)
	}
}

impl From<&'static str> for Address {
	fn from(s: &'static str) -> Self {
		s.parse().unwrap()
	}
}

impl str::FromStr for Address {
	type Err = AddressError;

	fn from_str(s: &str) -> Result<Self, AddressError> {
		let v = bs58::decode(s)
			.into_vec()
			.map_err(|_| AddressError::InvalidAddress)?;

		Address::from_slice(&v)
	}
}

/// Bitcoin data checksum
#[inline]
pub fn checksum(data: &[u8]) -> Hash32 {
	let mut result = Hash32::default();
	result.copy_from_slice(&sha256d::Hash::hash(data)[0..4]);
	result
}

#[cfg(test)]
mod tests {
	use super::{Address, Format, Hash160, Network};

	#[test]
	fn test_address_to_string_p2pkh() {
		let address = Address {
			format: Format::P2PKH,
			network: Network::Mainnet,
			hash: Hash160::from("3f4aa1fedf1f54eeb03b759deadb36676b184911"),
		};

		assert_eq!(
			String::from("16meyfSoQV6twkAAxPe51RtMVz7PGRmWna"),
			address.to_string()
		);
	}

	#[test]
	fn test_address_to_string_p2sh() {
		let address = Address {
			format: Format::P2SH,
			network: Network::Mainnet,
			hash: Hash160::from("f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"),
		};

		assert_eq!(
			String::from("3Q3zY87DrUmE371Grgc7bsDiVPqpu4mN1f"),
			address.to_string()
		);
	}

	#[test]
	fn test_address_from_str_p2pkh() {
		let address = Address {
			format: Format::P2PKH,
			network: Network::Mainnet,
			hash: Hash160::from("3f4aa1fedf1f54eeb03b759deadb36676b184911"),
		};

		assert_eq!(address, "16meyfSoQV6twkAAxPe51RtMVz7PGRmWna".into());
	}

	#[test]
	fn test_address_from_str_p2sh() {
		let address = Address {
			format: Format::P2SH,
			network: Network::Mainnet,
			hash: Hash160::from("f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"),
		};

		assert_eq!(address, "3Q3zY87DrUmE371Grgc7bsDiVPqpu4mN1f".into());
	}

	#[test]
	fn test_checksum() {
		assert_eq!(
			super::checksum(b"test checksum"),
			super::Hash32::from("4b38b54d")
		);
	}
}
