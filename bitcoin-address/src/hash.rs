// TODO: Implement common traits using macros

use std::{fmt, ops, str};

use bitcoin_hashes::hex::{Error, FromHex, ToHex};

/// Hash with SHA256 and RIPEMD160 applied
#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
pub struct Hash160([u8; 20]);

impl Hash160 {
    pub fn new(data: [u8; 20]) -> Self {
        Hash160(data)
    }
}

impl Default for Hash160 {
    fn default() -> Self {
        Hash160([0u8; 20])
    }
}

impl ops::Deref for Hash160 {
    type Target = [u8; 20];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ops::DerefMut for Hash160 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl fmt::Debug for Hash160 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0.to_hex())
    }
}

impl fmt::Display for Hash160 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0.to_hex())
    }
}

impl From<&str> for Hash160 {
    fn from(s: &str) -> Self {
        s.parse().unwrap()
    }
}

impl str::FromStr for Hash160 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec: Vec<u8> = Vec::from_hex(s)?;
        match vec.len() {
            20 => {
                let mut result = [0u8; 20];
                result.copy_from_slice(&vec);
                Ok(Hash160(result))
            }
            _ => Err(Error::InvalidLength(20, vec.len())),
        }
    }
}

/// Truncated hash
#[repr(C)]
#[derive(Clone, Copy, PartialEq)]
pub struct Hash32([u8; 4]);

impl Hash32 {
    pub fn new(data: [u8; 4]) -> Self {
        Hash32(data)
    }
}

impl Default for Hash32 {
    fn default() -> Self {
        Hash32([0u8; 4])
    }
}

impl ops::Deref for Hash32 {
    type Target = [u8; 4];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ops::DerefMut for Hash32 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0.to_hex())
    }
}

impl From<&str> for Hash32 {
    fn from(s: &str) -> Self {
        s.parse().unwrap()
    }
}

impl str::FromStr for Hash32 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec: Vec<u8> = Vec::from_hex(s)?;
        match vec.len() {
            4 => {
                let mut result = [0u8; 4];
                result.copy_from_slice(&vec);
                Ok(Hash32(result))
            }
            _ => Err(Error::InvalidLength(4, vec.len())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Hash160, Hash32};

    #[test]
    fn test_hash160() {
        assert_eq!(
            Hash160::new([
                0xda, 0x0b, 0x34, 0x52, 0xb0, 0x6f, 0xe3, 0x41, 0x62, 0x6a, 0xd0, 0x94, 0x9c, 0x18,
                0x3f, 0xbd, 0xa5, 0x67, 0x68, 0x26,
            ]),
            Hash160::from("da0b3452b06fe341626ad0949c183fbda5676826")
        );
    }

    #[test]
    fn test_hash32() {
        assert_eq!(
            Hash32::new([0xda, 0x0b, 0x34, 0xb0,]),
            Hash32::from("da0b34b0")
        );
    }
}
