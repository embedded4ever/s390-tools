// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::io::{BufRead, BufReader, Read};

use enum_dispatch::enum_dispatch;
use pv::misc::decode_hex;

use super::{try_copy_slice_to_array, KeyExchangeTrait, SeHdr};
use crate::error::{Error, Result};

/// The `enum_dispatch` macros needs at least one local trait to be implemented.
#[allow(unused)]
#[enum_dispatch(UvKeyHashes)]
trait UvKeyHashTrait: AsRef<[u8]> {}

#[derive(Debug, PartialEq, Eq)]
pub struct UvKeyHashV1([u8; 32]);

#[allow(dead_code)]
#[non_exhaustive]
#[enum_dispatch]
#[derive(PartialEq, Eq, Debug)]
pub enum UvKeyHash {
    UvKeyHashV1(UvKeyHashV1),
}

impl AsRef<[u8]> for UvKeyHash {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::UvKeyHashV1(hash) => hash.as_ref(),
        }
    }
}

impl UvKeyHashV1 {
    pub fn new<T: AsRef<[u8]>>(data: T) -> Result<Self> {
        let array = try_copy_slice_to_array(data.as_ref())?;
        Ok(Self(array))
    }
}

use std::fmt::{self, Display};
use std::ops::{Index, IndexMut};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UvKeyHashV1Kind {
    PCHKH,
    PBHKH,
    PCHHKH,
    PBHHKH,
}

impl Display for UvKeyHashV1Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PCHKH => write!(f, "Classical Host key hash"),
            Self::PBHKH => write!(f, "Backup classical host key hash"),
            Self::PCHHKH => write!(f, "Hybrid host key hash"),
            Self::PBHHKH => write!(f, "Backup hybrid host key hash"),
        }
    }
}

/// Index into the UV key hash array.
///
/// The indices follow the UV specification layout:
/// - 0: PCHKH (Classical host key hash)
/// - 1: PBHKH (Backup classical host key hash)
/// - 2-3: Reserved for future use
/// - 4: PCHHKH (Hybrid host key hash)
/// - 5: PBHHKH (Backup hybrid host key hash)
/// - 6-14: Reserved for future use
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UvKeyHashIdx(u8);

impl UvKeyHashIdx {
    pub const PCHKH: Self = Self(0);
    pub const PBHKH: Self = Self(1);
    pub const PCHHKH: Self = Self(4);
    pub const PBHHKH: Self = Self(5);

    pub fn index(self) -> usize {
        self.0 as usize
    }

    pub fn kind(self) -> Option<UvKeyHashV1Kind> {
        match self.0 {
            0 => Some(UvKeyHashV1Kind::PCHKH),
            1 => Some(UvKeyHashV1Kind::PBHKH),
            4 => Some(UvKeyHashV1Kind::PCHHKH),
            5 => Some(UvKeyHashV1Kind::PBHHKH),
            _ => None,
        }
    }
}

impl TryFrom<usize> for UvKeyHashIdx {
    type Error = ();

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0..=14 => Ok(Self(value as u8)),
            _ => Err(()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct UvKeyHashesV1 {
    pub hashes: [UvKeyHashV1; 15],
}

impl Index<UvKeyHashIdx> for UvKeyHashesV1 {
    type Output = UvKeyHashV1;

    fn index(&self, pos: UvKeyHashIdx) -> &Self::Output {
        &self.hashes[pos.index()]
    }
}

impl IndexMut<UvKeyHashIdx> for UvKeyHashesV1 {
    fn index_mut(&mut self, pos: UvKeyHashIdx) -> &mut Self::Output {
        &mut self.hashes[pos.index()]
    }
}

#[derive(Debug)]
pub struct MatchingUvKeyHash<'a> {
    pub idx: UvKeyHashIdx,
    pub hash: &'a UvKeyHashV1,
}

impl UvKeyHashesV1 {
    pub fn matching_hashes(&self, hdr: &SeHdr) -> Vec<MatchingUvKeyHash<'_>> {
        self.hashes
            .iter()
            .enumerate()
            .filter(|(_, hash)| hdr.contains_hash(hash))
            .filter_map(|(idx, hash)| {
                Some(MatchingUvKeyHash {
                    idx: idx.try_into().ok()?,
                    hash,
                })
            })
            .collect()
    }
}

impl UvKeyHashV1 {
    pub const UV_KEY_HASH_SIZE: usize = 32;
    pub const UV_KEY_HASH_NULL: Self = Self([0x0_u8; Self::UV_KEY_HASH_SIZE]);
}

impl AsRef<[u8]> for UvKeyHashV1 {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<&str> for UvKeyHashV1 {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = decode_hex(value)?;
        if bytes.len() != 32 {
            return Err(Error::InvalidTargetKeyHash);
        }

        Ok(Self(bytes.try_into().unwrap()))
    }
}

impl TryFrom<String> for UvKeyHashV1 {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl UvKeyHashesV1 {
    pub const SYS_UV_KEYS_ALL: &'static str = "/sys/firmware/uv/keys/all";

    /// Reads a `UvKeyHashesV1` from an [`std::io::Read`].
    ///
    /// # Errors
    ///
    /// This function will return an error if this functions encounters an I/O
    /// error, if a line could not be interpreted as `UvKeyHashV1` or if the
    /// count of hashes is less than 15.
    #[allow(clippy::similar_names)]
    pub fn read_from_io<R>(reader: R) -> Result<Self>
    where
        R: Read,
    {
        let buf_reader = BufReader::new(reader);
        let lines: Vec<String> = buf_reader
            .lines()
            .collect::<std::result::Result<Vec<_>, std::io::Error>>()?;
        let hashes: Vec<UvKeyHashV1> = lines
            .into_iter()
            .map(UvKeyHashV1::try_from)
            .collect::<std::result::Result<Vec<UvKeyHashV1>, Error>>()?;
        let hashes_count = hashes.len();
        if hashes_count < 15 {
            return Err(Error::InvalidUvKeyHashes);
        }

        let hashes: [UvKeyHashV1; 15] = hashes.try_into().map_err(|_| Error::InvalidUvKeyHashes)?;
        Ok(Self { hashes })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use pv::misc::decode_hex;

    use crate::pv_utils::uv_keys::UvKeyHashV1;
    use crate::uvdata::UvKeyHashesV1;

    #[test]
    fn from_reader() {
        let data = "0b729fd62241b339840d61b964a06bb6a1fd4976d9ebea2b4fb48d44de3a2461
8ec6bc2f77d5d6474b1417cf0a8c914f576245a5b9bb0eefacc7b821483ece7d
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
";
        let result = UvKeyHashesV1::read_from_io(Cursor::new(data)).expect("should not fail");
        let mut exp_hashes = [UvKeyHashV1::UV_KEY_HASH_NULL; 15];
        exp_hashes[0] = UvKeyHashV1::new(
            decode_hex("0b729fd62241b339840d61b964a06bb6a1fd4976d9ebea2b4fb48d44de3a2461").unwrap(),
        )
        .unwrap();

        exp_hashes[1] = UvKeyHashV1::new(
            decode_hex("8ec6bc2f77d5d6474b1417cf0a8c914f576245a5b9bb0eefacc7b821483ece7d").unwrap(),
        )
        .unwrap();

        let uv_hashes = UvKeyHashesV1 { hashes: exp_hashes };
        assert_eq!(result, uv_hashes);
    }
}
