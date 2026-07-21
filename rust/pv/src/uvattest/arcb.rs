// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::mem::size_of;

use pv_core::static_assert;
use zerocopy::{BigEndian, FromBytes, Immutable, IntoBytes, KnownLayout, U32};

use super::additional::{FW_STATE_SIZE, PHKH_SIZE, SECRET_STORE_HASH_SIZE};
use super::AttNonce;
use crate::attest::{AttestationMagic, AttestationMeasAlg};
use crate::crypto::random_array;
use crate::misc::Flags;
use crate::req::{Aad, BinReqValues, HostKey, Keyslot, ReqEncrCtx};
use crate::request::{Confidential, MagicValue, Request, RequestVersion, SymKey, Zeroize};
use crate::uv::UvFlags;
use crate::{assert_size, Error, Result};
#[cfg(doc)]
use crate::{
    request::SymKeyType,
    uv::AttestationCmd,
    verify::{CertVerifier, HkdVerifier},
};

/// Retrieve Attestation Request Control Block
///
/// An ARCB holds an Attestation Measurement key to attest a SE-guest.
/// The (architectural optional) nonce is always used and freshly generated for a new
/// [`AttestationRequest`].
///
/// Layout:
/// ```none
/// _______________________________________________________________
/// |                   generic header (48)
/// |     ---------------------------------------------------     |
/// |  Plaintext Attestation flags (8)                            |
/// |  Measurement Algorithm Identifier (4)                       |
/// |  Reserved(4)                                                |
/// |  Customer Public Key (160) generated for each request       |
/// |  N Keyslots(80 each)                                        |
/// |     ---------------------------------------------------     |
/// |  Measurement key (64)                                       | Encrypted
/// |  Optional Nonce (0 or  16)                                  | Encrypted
/// |     ---------------------------------------------------     |
/// |                   AES GCM Tag (16)                          |
/// |_____________________________________________________________|
/// ```
///
/// # Example
/// Create an Attestation request with default flags (= use a nonce)
///
/// ```rust,no_run
/// # use s390_pv::attest::{AttestationFlags, AttestationMeasAlg, AttestationRequest, AttestationVersion};
/// # use s390_pv::request::{SymKeyType, Request, ReqEncrCtx, HostKey};
/// # fn main() -> s390_pv::Result<()> {
/// let att_version = AttestationVersion::One;
/// let meas_alg = AttestationMeasAlg::HmacSha512;
/// let mut arcb = AttestationRequest::new(att_version, meas_alg, AttestationFlags::default())?;
/// // read-in hostkey document(s). Not verified for brevity.
/// let hkd = s390_pv::misc::read_certs(&std::fs::read("host-key-document.crt")?)?;
/// // IBM issued HKD certificates typically have one X509
/// let hkd = hkd.first().unwrap().public_key()?;
/// arcb.add_hostkey(HostKey::V1(hkd));
/// // you can add multiple hostkeys
/// // arcb.add_hostkey(HostKey::V1(another_hkd));
/// // encrypt it
/// let ctx = ReqEncrCtx::random(SymKeyType::Aes256Gcm)?;
/// let arcb = arcb.encrypt(&ctx)?;
/// # Ok(())
/// # }
/// ```
/// # See Also
///
/// * [`AttestationFlags`]
/// * [`AttestationMeasAlg`]
/// * [`AttestationVersion`]
/// * [`SymKeyType`]
/// * [`Request`]
/// * [`ReqEncrCtx`]
/// * [`AttestationCmd`]
/// * [`HkdVerifier`], [`CertVerifier`]
#[derive(Debug)]
pub struct AttestationRequest {
    version: AttestationVersion,
    aad: AttestationAuthenticated,
    keyslots: Vec<Keyslot>,
    conf: Confidential<ReqConfData>,
}

impl AttestationRequest {
    /// Create a new retrieve attestation measurement request
    pub fn new(
        version: AttestationVersion,
        mai: AttestationMeasAlg,
        mut flags: AttestationFlags,
    ) -> Result<Self> {
        // This implementation enforces using a nonce
        flags.set_nonce();
        Ok(Self {
            version,
            aad: AttestationAuthenticated::new(flags, mai),
            keyslots: vec![],
            conf: ReqConfData::random()?,
        })
    }

    /// Returns a reference to the flags of this [`AttestationRequest`].
    pub fn flags(&self) -> &AttestationFlags {
        self.aad.flags()
    }

    /// Returns the request version, derived from the type of added host-keys.
    /// Returns [`AttestationVersion::One`] if no host-keys have been added yet.
    pub fn version(&self) -> AttestationVersion {
        self.version
    }

    /// Returns a copy of the confidential data of this [`AttestationRequest`].
    ///
    /// Gives a copy of the confidential data of this request for further
    /// processing. This data should be never exposed in cleartext to anyone but
    /// the creator and the verifier of this request.
    pub fn confidential_data(&self) -> AttestationConfidential {
        let conf = self.conf.value();
        AttestationConfidential::new(conf.meas_key.to_vec(), conf.nonce.into())
    }

    fn aad(&self, ctx: &ReqEncrCtx) -> Result<Vec<u8>> {
        let cust_pub_key = ctx.key_coords()?;
        let mut aad: Vec<Aad> = Vec::with_capacity(self.keyslots.len() + 2);
        aad.push(Aad::Plain(self.aad.as_bytes()));
        aad.push(Aad::Plain(cust_pub_key.as_ref()));
        self.keyslots.iter().for_each(|k| aad.push(Aad::Ks(k)));
        ctx.build_aad(
            self.version.into(),
            &aad,
            size_of::<ReqConfData>(),
            AttestationMagic::MAGIC,
        )
    }

    /// Checks for magic and returns [`BinReqValues`]
    fn bin_values(arcb: &[u8]) -> Result<BinReqValues<'_>> {
        if !AttestationMagic::starts_with_magic(arcb) {
            return Err(Error::NoArcb);
        }

        let values = BinReqValues::get(arcb)?;
        match values.version().try_into()? {
            AttestationVersion::One => (),
            AttestationVersion::Two => (),
        };

        Ok(values)
    }

    /// Returns the authenticated area of an binary attestation request.
    ///
    /// # Error
    ///
    /// Returns an error if the request is malformed.
    pub fn auth_bin(arcb: &[u8]) -> Result<AttestationAuthenticated> {
        let values = Self::bin_values(arcb)?;
        let auth: &AttestationAuthenticated = values.req_dep_aad().ok_or(Error::BinRequestSmall)?;
        Ok(auth.to_owned())
    }

    /// Decrypts the request and extracts the authenticated and confidential data.
    ///
    /// Deconstructs the `arcb` and decrypts it using `arpk`.
    ///
    /// # Error
    ///
    /// Returns an error if the request is malformed or the decryption failed.
    pub fn decrypt_bin(
        arcb: &[u8],
        arpk: &SymKey,
    ) -> Result<(AttestationAuthenticated, AttestationConfidential)> {
        let values = Self::bin_values(arcb)?;
        let auth = Self::auth_bin(arcb)?;

        let mai = auth.mai.try_into()?;
        let keysize = match mai {
            v @ AttestationMeasAlg::HmacSha512 => v.exp_size(),
        } as usize;

        if keysize > values.sea() as usize {
            return Err(Error::BinArcbSeaSmall(values.sea()));
        }

        let decr = values.decrypt(arpk)?;

        // size sanitized by fence before
        let meas_key = &decr.value()[..keysize];
        let nonce = if decr.value().len() == size_of::<ReqConfData>() {
            Some(
                (&decr.value()[keysize..decr.value().len()])
                    .try_into()
                    .unwrap(),
            )
        } else {
            None
        };
        let conf = AttestationConfidential::new(meas_key.to_vec(), nonce);

        Ok((auth.to_owned(), conf))
    }
}

/// Confidential Data of an attestation request
///
/// contains a measurement key and an optional nonce
#[derive(Debug)]
pub struct AttestationConfidential {
    measurement_key: Confidential<Vec<u8>>,
    nonce: Option<Confidential<AttNonce>>,
}

impl AttestationConfidential {
    /// Returns a reference to the measurement key of this [`AttestationConfidential`].
    pub fn measurement_key(&self) -> &[u8] {
        self.measurement_key.value()
    }

    /// Returns a reference to the nonce of this [`AttestationConfidential`].
    pub fn nonce(&self) -> &Option<Confidential<AttNonce>> {
        &self.nonce
    }

    fn new(measurement_key: Vec<u8>, nonce: Option<AttNonce>) -> Self {
        Self {
            measurement_key: measurement_key.into(),
            nonce: nonce.map(Confidential::new),
        }
    }
}

impl Request for AttestationRequest {
    fn encrypt(&self, ctx: &ReqEncrCtx) -> Result<Vec<u8>> {
        let conf = self.conf.value().as_bytes();
        let aad = self.aad(ctx)?;
        ctx.encrypt_aead(&aad, conf).map(|res| res.into_buf())
    }

    fn add_hostkey(&mut self, hostkey: HostKey) {
        self.keyslots.push(Keyslot::new(hostkey))
    }
}

/// Versions for [`AttestationRequest`]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationVersion {
    /// Version 1 (= 0x0100)
    One = 0x0100,
    /// Version 2 (= 0x0200)
    Two = 0x0200,
}

impl TryFrom<u32> for AttestationVersion {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        if value == Self::One as u32 {
            Ok(Self::One)
        } else if value == Self::Two as u32 {
            Ok(Self::Two)
        } else {
            Err(Error::BinArcbInvVersion(value))
        }
    }
}

impl From<AttestationVersion> for RequestVersion {
    fn from(val: AttestationVersion) -> Self {
        val as Self
    }
}

/// Authenticated additional Data of an [`AttestationRequest`]
#[repr(C)]
#[derive(Debug, IntoBytes, FromBytes, Clone, Copy, Immutable, KnownLayout)]
pub struct AttestationAuthenticated {
    flags: AttestationFlags,
    mai: U32<BigEndian>,
    res: u32,
}
assert_size!(AttestationAuthenticated, 0x10);

impl AttestationAuthenticated {
    fn new(flags: AttestationFlags, mai: AttestationMeasAlg) -> Self {
        Self {
            flags,
            mai: mai.into(),
            res: 0,
        }
    }

    /// Returns a reference to the flags of this [`AttestationAuthenticated`].
    pub fn flags(&self) -> &AttestationFlags {
        &self.flags
    }

    /// Returns the [`AttestationMeasAlg`] of this [`AttestationAuthenticated`].
    ///
    /// # Panics
    ///
    /// Panics if the library failed to set up the MAI correctly.
    pub fn mai(&self) -> AttestationMeasAlg {
        AttestationMeasAlg::try_from(self.mai).expect("ReqAuthData invariant hurt. Invalid MAI")
    }
}

/// Attestation flags
#[repr(C)]
#[derive(Default, Debug, IntoBytes, FromBytes, Clone, Copy, Immutable)]
pub struct AttestationFlags(UvFlags);
static_assert!(AttestationFlags::FLAG_TO_ADD_SIZE.len() < 64);

impl AttestationFlags {
    /// Maps the flag to the (maximum) required size for the additional data
    pub(crate) const FLAG_TO_ADD_SIZE: [u32; 6] = [
        0,
        0,
        PHKH_SIZE,
        PHKH_SIZE,
        SECRET_STORE_HASH_SIZE,
        FW_STATE_SIZE,
    ];

    /// Returns the maximum size this flag requires for additional data
    pub fn expected_additional_size(&self) -> u32 {
        Self::FLAG_TO_ADD_SIZE
            .iter()
            .enumerate()
            .fold(0, |size, (b, s)| size + self.0.is_set(b as u8) as u32 * s)
    }

    /// Flag 1 - use a nonce
    ///
    /// This attestation implementation forces the use of a nonce, so this will always be on and
    /// the function is non-public
    fn set_nonce(&mut self) {
        self.0.set_bit(1);
    }

    /// Flag 2 - request the image public host-key hash
    ///
    /// Asks the Ultravisor to provide the host-key hash that unpacked the SE-image to be added in
    /// additional data. Requires 32 bytes.
    pub fn set_image_phkh(&mut self) {
        self.0.set_bit(2);
    }

    /// Check weather the image public host key hash flag is on
    pub fn image_phkh(&self) -> bool {
        self.0.is_set(2)
    }

    /// Flag 3 - request the attestation public host-key hash
    ///
    /// Asks the Ultravisor to provide the host-key hash that unpacked the attestation request to
    /// be added in additional data. Requires 32 bytes.
    pub fn set_attest_phkh(&mut self) {
        self.0.set_bit(3);
    }

    /// Check weather the attestation public host key hash flag is on
    pub fn attest_phkh(&self) -> bool {
        self.0.is_set(3)
    }

    /// Flag 4 - request the state of the secret store
    ///
    /// Asks the Ultravisor to provide the hash of the added secret requests. Requires 64 bytes.
    pub fn set_secret_store_hash(&mut self) {
        self.0.set_bit(4);
    }

    /// Check weather the hash of the added secret requests flag is on
    pub fn secret_store_hash(&self) -> bool {
        self.0.is_set(4)
    }

    /// Flag 5 - request the firmware hash
    ///
    /// Asks the Ultravisor to provide the hash of the firmware. Requires 320 bytes.
    pub fn set_firmware_state(&mut self) {
        self.0.set_bit(5);
    }

    /// Check weather the hash of the added secret requests flag is on
    pub fn firmware_state(&self) -> bool {
        self.0.is_set(5)
    }
}

#[repr(C)]
#[derive(Debug, IntoBytes, Immutable)]
struct ReqConfData {
    meas_key: [u8; 64],
    nonce: AttNonce,
}
assert_size!(ReqConfData, 80);

impl ReqConfData {
    fn random() -> Result<Confidential<Self>> {
        Ok(Confidential::new(Self {
            meas_key: random_array()?,
            nonce: random_array()?,
        }))
    }
}

impl Zeroize for ReqConfData {
    fn zeroize(&mut self) {
        self.meas_key.zeroize();
        self.nonce.zeroize();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::get_test_asset;
    use crate::request::{HybridPKey, SymKey};
    use crate::test_utils::{get_test_keys, get_test_keys_hybrid};

    const ARPK: [u8; 32] = [0x17; 32];
    const NONCE: [u8; 16] = [0xab; 16];
    const MEAS: [u8; 64] = [0x77; 64];

    fn mk_arcb() -> Vec<u8> {
        let (cust_key, host_key) = get_test_keys();
        let host_key = HostKey::V1(host_key);

        let ctx = ReqEncrCtx::new_aes_256(
            Some([0x55; 12]),
            Some(cust_key),
            Some(SymKey::Aes256(ARPK.into())),
        )
        .unwrap();

        let mut flags = AttestationFlags::default();
        flags.set_image_phkh();
        flags.set_attest_phkh();

        let mut arcb = AttestationRequest::new(
            AttestationVersion::One,
            AttestationMeasAlg::HmacSha512,
            flags,
        )
        .unwrap();

        // manually set confidential data (API does not allow this)
        arcb.conf.value_mut().nonce = NONCE;
        arcb.conf.value_mut().meas_key = MEAS;

        arcb.add_hostkey(host_key);
        arcb.encrypt(&ctx).unwrap()
    }

    fn mk_arcb_v2() -> Vec<u8> {
        let (cust_key, host_key1, host_key2) = get_test_keys_hybrid();
        let host_key = HostKey::V2(HybridPKey::new(host_key1, host_key2).unwrap());

        let ctx = ReqEncrCtx::new_aes_256(
            Some([0x55; 12]),
            Some(cust_key),
            Some(SymKey::Aes256(ARPK.into())),
        )
        .unwrap();

        let mut flags = AttestationFlags::default();
        flags.set_image_phkh();
        flags.set_attest_phkh();

        let mut arcb = AttestationRequest::new(
            AttestationVersion::Two,
            AttestationMeasAlg::HmacSha512,
            flags,
        )
        .unwrap();

        // manually set confidential data (API does not allow this)
        arcb.conf.value_mut().nonce = NONCE;
        arcb.conf.value_mut().meas_key = MEAS;

        arcb.add_hostkey(host_key);
        arcb.encrypt(&ctx).unwrap()
    }

    #[test]
    fn arcb() {
        let request = mk_arcb();
        let exp = get_test_asset!("exp/arcb.bin");

        assert_eq!(request, exp);
    }

    #[test]
    fn arcb_v2() {
        let request = mk_arcb_v2();
        // Expected bytes for a V2 ARCB: rqvn = 0x0200 (bytes 8-11), rest deterministic.
        // The first 288 bytes cover header + customer-public-key + one V2 keyslot header.
        let exp: [u8; 288] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 7, 208, 85, 85, 85, 85, 85, 85, 85, 85, 85,
            85, 85, 85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 80, 112, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 199,
            93, 52, 249, 22, 82, 219, 69, 123, 11, 32, 156, 70, 164, 145, 164, 78, 226, 177, 110,
            35, 194, 216, 218, 241, 22, 103, 138, 98, 242, 76, 227, 50, 197, 153, 95, 8, 69, 107,
            102, 177, 109, 213, 90, 146, 197, 7, 241, 227, 26, 247, 140, 100, 168, 46, 122, 84, 27,
            21, 19, 80, 21, 242, 2, 134, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 64, 128, 88,
            167, 241, 165, 195, 80, 151, 83, 58, 2, 169, 56, 121, 231, 222, 103, 186, 40, 11, 206,
            131, 101, 236, 148, 178, 185, 8, 245, 137, 195, 169, 152, 216, 190, 30, 99, 7, 215, 74,
            224, 26, 220, 70, 130, 95, 246, 187, 111, 160, 92, 17, 71, 207, 226, 204, 244, 162, 79,
            61, 131, 61, 218, 112, 255, 94, 191, 53, 220, 196, 47, 37, 93, 227, 234, 101, 1, 174,
            171, 68, 42, 136, 92, 238, 72, 6, 17, 77, 231, 225, 174, 22, 222, 188, 212, 15, 248,
            145, 72, 126, 139, 17, 233, 225, 156, 46, 233, 151, 54, 2, 175, 88, 215, 254, 243, 222,
            37, 81, 50, 110, 18, 76, 252, 12, 210, 146, 66, 23,
        ];

        // only compare non-randomized part
        assert_eq!(request[..288], exp[..288]);
    }

    #[test]
    fn auth_bin() {
        let request = mk_arcb();
        let auth_bin = AttestationRequest::auth_bin(&request).unwrap();
        let exp = &request[0x30..0x40];

        assert_eq!(exp, auth_bin.as_bytes());
    }

    #[test]
    fn auth_bin_v2() {
        let request = mk_arcb_v2();
        let auth_bin = AttestationRequest::auth_bin(&request).unwrap();
        let exp = &request[0x30..0x40];

        assert_eq!(exp, auth_bin.as_bytes());
    }

    #[test]
    fn decrypt_bin() {
        let request = mk_arcb();
        let arpk = SymKey::Aes256(ARPK.into());
        let (_, conf) = AttestationRequest::decrypt_bin(&request, &arpk).unwrap();
        assert_eq!(conf.measurement_key(), &MEAS);
        assert_eq!(conf.nonce().as_ref().unwrap().value(), &NONCE);
    }

    #[test]
    fn decrypt_bin_v2() {
        let request = mk_arcb_v2();
        let arpk = SymKey::Aes256(ARPK.into());
        let (_, conf) = AttestationRequest::decrypt_bin(&request, &arpk).unwrap();
        assert_eq!(conf.measurement_key(), &MEAS);
        assert_eq!(conf.nonce().as_ref().unwrap().value(), &NONCE);
    }

    #[test]
    fn arcb_v1_version() {
        // Without any host-keys, version defaults to One
        let arcb = AttestationRequest::new(
            AttestationVersion::One,
            AttestationMeasAlg::HmacSha512,
            AttestationFlags::default(),
        )
        .unwrap();

        assert_eq!(arcb.version(), AttestationVersion::One);
    }

    #[test]
    fn arcb_v2_version() {
        // After adding a V2 host-key, version is Two
        let mut arcb = AttestationRequest::new(
            AttestationVersion::Two,
            AttestationMeasAlg::HmacSha512,
            AttestationFlags::default(),
        )
        .unwrap();
        let (_, host_key1, host_key2) = get_test_keys_hybrid();
        arcb.add_hostkey(HostKey::V2(HybridPKey::new(host_key1, host_key2).unwrap()));

        assert_eq!(arcb.version(), AttestationVersion::Two);
    }

    #[test]
    fn attestation_version_try_from() {
        // Test version conversion from u32
        assert_eq!(
            AttestationVersion::try_from(0x0100).unwrap(),
            AttestationVersion::One
        );
        assert_eq!(
            AttestationVersion::try_from(0x0200).unwrap(),
            AttestationVersion::Two
        );

        // Invalid version should error
        assert!(AttestationVersion::try_from(0x0300).is_err());
    }

    #[test]
    fn attestation_flags_expected_size() {
        // Test expected additional data size calculation for V1
        let mut flags = AttestationFlags::default();

        // Image PHKH flag - should be 32 bytes
        flags.set_image_phkh();
        assert_eq!(flags.expected_additional_size(), 32);

        // Add attest PHKH flag - should be 64 bytes (32 + 32)
        flags.set_attest_phkh();
        assert_eq!(flags.expected_additional_size(), 64);

        // Add secret store hash - should be 128 bytes (64 + 64)
        flags.set_secret_store_hash();
        assert_eq!(flags.expected_additional_size(), 128);

        // Add firmware state - should be 448 bytes (128 + 320)
        flags.set_firmware_state();
        assert_eq!(flags.expected_additional_size(), 448);
    }

    #[test]
    fn confidential_data_v2() {
        // Test confidential data extraction (version-independent)
        let arcb = AttestationRequest::new(
            AttestationVersion::Two,
            AttestationMeasAlg::HmacSha512,
            AttestationFlags::default(),
        )
        .unwrap();

        let conf = arcb.confidential_data();

        // Should have measurement key and nonce
        assert_eq!(conf.measurement_key().len(), 64);
        assert!(conf.nonce().is_some());
        assert_eq!(conf.nonce().as_ref().unwrap().value().len(), 16);
    }

    #[test]
    fn decrypt_bin_fail_magic() {
        let arpk = SymKey::Aes256(ARPK.into());
        let mut tamp_arcb = mk_arcb();

        // tamper magic
        tamp_arcb[0] = 17;
        let ret = AttestationRequest::decrypt_bin(&tamp_arcb, &arpk);
        assert!(matches!(ret, Err(Error::NoArcb)));
    }

    #[test]
    fn decrypt_bin_fail_magic_v2() {
        let arpk = SymKey::Aes256(ARPK.into());
        let mut tamp_arcb = mk_arcb_v2();

        // tamper magic
        tamp_arcb[0] = 17;
        let ret = AttestationRequest::decrypt_bin(&tamp_arcb, &arpk);
        assert!(matches!(ret, Err(Error::NoArcb)));
    }

    #[test]
    fn decrypt_bin_fail_mai() {
        let arpk = SymKey::Aes256(ARPK.into());
        let mut tamp_arcb = mk_arcb();

        // tamper MAI
        tamp_arcb[0x3b] = 17;
        let ret = AttestationRequest::decrypt_bin(&tamp_arcb, &arpk);
        println!("{ret:?}");
        assert!(matches!(
            ret,
            Err(Error::PvCore(pv_core::Error::BinArcbInvAlgorithm(17)))
        ));
    }

    #[test]
    fn decrypt_bin_fail_mai_v2() {
        let arpk = SymKey::Aes256(ARPK.into());
        let mut tamp_arcb = mk_arcb_v2();

        // tamper MAI
        tamp_arcb[0x3b] = 17;
        let ret = AttestationRequest::decrypt_bin(&tamp_arcb, &arpk);
        println!("{ret:?}");
        assert!(matches!(
            ret,
            Err(Error::PvCore(pv_core::Error::BinArcbInvAlgorithm(17)))
        ));
    }

    #[test]
    fn decrypt_bin_fail_aad() {
        let arpk = SymKey::Aes256(ARPK.into());
        let mut tamp_arcb = mk_arcb();

        // tamper AAD
        tamp_arcb[0x3c] = 17;
        let ret = AttestationRequest::decrypt_bin(&tamp_arcb, &arpk);
        assert!(matches!(ret, Err(Error::GcmTagMismatch)));
    }

    #[test]
    fn decrypt_bin_fail_aad_v2() {
        let arpk = SymKey::Aes256(ARPK.into());
        let mut tamp_arcb = mk_arcb_v2();

        // tamper AAD
        tamp_arcb[0x3c] = 17;
        let ret = AttestationRequest::decrypt_bin(&tamp_arcb, &arpk);
        assert!(matches!(ret, Err(Error::GcmTagMismatch)));
    }
}
