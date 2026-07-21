// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use openssl::md::Md;
use openssl::pkey::{PKey, Private};
use pv_core::request::RequestVersion;
use pv_core::secret::AddSecretMagic;
use pv_core::static_assert;
use pv_core::uv::SecretId;
use zerocopy::{Immutable, IntoBytes};

use super::guest_secret::{ListableSecretHdr, SecretAuth};
use super::user_data::UserData;
use crate::crypto::{hkdf_rfc_5869, AeadEncryptionResult};
use crate::misc::Flags;
use crate::req::{Aad, BinReqValues, HostKey, Keyslot, ReqEncrCtx, RequestHdr};
use crate::request::{BootHdrTags, Confidential, Request};
use crate::secret::{ExtSecret, GuestSecret};
use crate::uv::{ConfigUid, UvFlags};
use crate::{assert_size, Error, Result};

/// Authenticated data w/o user data
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, Immutable)]
struct ReqAuthDataV1 {
    flags: UvFlags,
    boot_tags: BootHdrTags,
    cuid: ConfigUid,
    reserved90: [u8; 0x100],
}
assert_size!(ReqAuthDataV1, 0x1e8);

impl ReqAuthDataV1 {
    fn new<F: Into<UvFlags>>(boot_tags: BootHdrTags, flags: F) -> Self {
        Self {
            flags: flags.into(),
            boot_tags,
            cuid: [0; 0x10],
            reserved90: [0; 0x100],
        }
    }
}

/// Authenticated data w/o user data for v2 header: move up secret header 2
#[repr(C)]
#[derive(Debug, Clone, IntoBytes, Immutable)]
struct ReqAuthDataV2 {
    flags: UvFlags,
    boot_tags: BootHdrTags,
    cuid: ConfigUid,
    secr_auth: [u8; 0x30],
    reservedd0: [u8; 0x100 - 0x30],
}
assert_size!(ReqAuthDataV2, 0x1e8);

impl ReqAuthDataV2 {
    fn new<F: Into<UvFlags>>(boot_tags: BootHdrTags, flags: F, secr_auth: [u8; 0x30]) -> Self {
        Self {
            flags: flags.into(),
            boot_tags,
            cuid: [0; 0x10],
            secr_auth,
            reservedd0: [0; 0xd0],
        }
    }
}

#[derive(Debug)]
struct ReqConfData {
    secret: GuestSecret,
    extension_secret: Confidential<[u8; 32]>,
}

impl ReqConfData {
    fn to_bytes(&self) -> Confidential<Vec<u8>> {
        let secret = self.secret.confidential();

        let mut v = vec![0; secret.len() + 32];
        if !secret.is_empty() {
            v[..secret.len()].copy_from_slice(secret);
        }
        v[secret.len()..32 + secret.len()]
            .copy_from_slice(self.extension_secret.value().as_slice());
        v.into()
    }
}

/// Flags for [`AddSecretRequest`]
#[derive(Default, Clone, Copy, Debug)]
pub struct AddSecretFlags(UvFlags);
impl AddSecretFlags {
    /// Enables the disable-dump flag
    ///
    /// After the request was dispatched successfully,
    /// the UV will not provide any dump decryption information for the SE-guest anymore.
    pub fn set_disable_dump(&mut self) {
        self.0.set_bit(0)
    }
}

impl From<&u64> for AddSecretFlags {
    fn from(v: &u64) -> Self {
        Self(v.into())
    }
}

impl From<AddSecretFlags> for UvFlags {
    fn from(f: AddSecretFlags) -> Self {
        f.0
    }
}

/// Versions for [`AddSecretRequest`]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddSecretVersion {
    /// Version 1 (= 0x0100)
    One = 0x0100,
    /// Version 2 (= 0x0200)
    Two = 0x0200,

    #[cfg(not(doc))]
    #[cfg(any(debug_assertions, test))]
    /// Only for testing
    Inv = 0,
}

impl TryFrom<u32> for AddSecretVersion {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        if value == Self::One as u32 {
            Ok(Self::One)
        } else if value == Self::Two as u32 {
            Ok(Self::Two)
        } else {
            Err(Error::BinAsrcbInvVersion(value))
        }
    }
}

impl From<AddSecretVersion> for RequestVersion {
    fn from(val: AddSecretVersion) -> Self {
        val as Self
    }
}

impl From<crate::request::SeHdrVersion> for AddSecretVersion {
    fn from(val: crate::request::SeHdrVersion) -> Self {
        match val {
            crate::request::SeHdrVersion::One => AddSecretVersion::One,
            crate::request::SeHdrVersion::Two => AddSecretVersion::Two,
        }
    }
}

/// Trait for authenticated data in add-secret requests.
///
/// This trait provides a common interface for different versions of authenticated data,
/// allowing flexible addition of new versions in the future.
trait ReqAuthData: IntoBytes + Immutable {
    /// Get the configuration UID
    fn cuid(&self) -> &ConfigUid;

    /// Set the configuration UID
    fn set_cuid(&mut self, cuid: ConfigUid);

    /// Get the boot tags
    fn boot_tags(&self) -> &BootHdrTags;

    /// Get the flags
    fn flags(&self) -> &UvFlags;
}

impl ReqAuthData for ReqAuthDataV1 {
    fn cuid(&self) -> &ConfigUid {
        &self.cuid
    }

    fn set_cuid(&mut self, cuid: ConfigUid) {
        self.cuid = cuid;
    }

    fn boot_tags(&self) -> &BootHdrTags {
        &self.boot_tags
    }

    fn flags(&self) -> &UvFlags {
        &self.flags
    }
}

impl ReqAuthData for ReqAuthDataV2 {
    fn cuid(&self) -> &ConfigUid {
        &self.cuid
    }

    fn set_cuid(&mut self, cuid: ConfigUid) {
        self.cuid = cuid;
    }

    fn boot_tags(&self) -> &BootHdrTags {
        &self.boot_tags
    }

    fn flags(&self) -> &UvFlags {
        &self.flags
    }
}

/// Enum holding version-specific authenticated data
#[derive(Debug)]
enum ReqAuthDataVersion {
    V1(ReqAuthDataV1),
    V2(ReqAuthDataV2),
}

impl ReqAuthDataVersion {
    fn new(
        version: AddSecretVersion,
        boot_tags: BootHdrTags,
        flags: AddSecretFlags,
        conf_data: &SecretAuth,
    ) -> Result<Self> {
        Ok(match version {
            AddSecretVersion::One => Self::V1(ReqAuthDataV1::new(boot_tags, flags)),
            AddSecretVersion::Two => Self::V2(ReqAuthDataV2::new(
                boot_tags,
                flags,
                conf_data.get(version).try_into().expect(
                    "SecretAuth::get() must return exactly 0x30 bytes for AddSecretVersion::Two",
                ),
            )),
            #[cfg(any(debug_assertions, test))]
            AddSecretVersion::Inv => panic!("Invalid version for production use"),
        })
    }

    #[allow(dead_code)]
    fn cuid(&self) -> &ConfigUid {
        match self {
            Self::V1(v) => v.cuid(),
            Self::V2(v) => v.cuid(),
        }
    }

    fn set_cuid(&mut self, cuid: ConfigUid) {
        match self {
            Self::V1(v) => v.set_cuid(cuid),
            Self::V2(v) => v.set_cuid(cuid),
        }
    }

    fn boot_tags(&self) -> &BootHdrTags {
        match self {
            Self::V1(v) => v.boot_tags(),
            Self::V2(v) => v.boot_tags(),
        }
    }

    #[allow(dead_code)]
    fn flags(&self) -> &UvFlags {
        match self {
            Self::V1(v) => v.flags(),
            Self::V2(v) => v.flags(),
        }
    }

    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::V1(v) => v.as_bytes(),
            Self::V2(v) => v.as_bytes(),
        }
    }
}

/// Add-secret request Control Block
///
/// An ASRCB wraps a secret to securely transport it to the Ultravisor.
///
/// Layout V2:
/// ```none
/// _______________________________________________________________
/// |                   generic header (48)
/// |     ---------------------------------------------------     |
/// |  Plaintext Add-Secret flags (8)                             |
/// |  SE header tags: PLD(64) ALD(64) TLD(64) HeaderTag(16)      |
/// |  Configuration unique ID(16) (Attestation)                  |
/// |       Optional, defaults to 0                               |
/// |  Secret header (48)                                         |
/// |  Reserved(208)                                              |
/// |  User Data(512) (reserved)                                  |
/// |  Customer Public Key (160) generated for each request       |
/// |  N Keyslots(1680 each)                                      |
/// |     ---------------------------------------------------     |
/// |  Secret to add (Secret type dependent)(may be 0 bytes)      | Encrypted
/// |  Extension secret(32) Optional, defaults to 0               | Encrypted
/// |     ---------------------------------------------------     |
/// |                   AES GCM Tag (16)                          |
/// |_____________________________________________________________|
/// ```
///
/// Layout V1:
/// ```none
/// _______________________________________________________________
/// |                   generic header (48)
/// |     ---------------------------------------------------     |
/// |  Plaintext Add-Secret flags (8)                             |
/// |  SE header tags: PLD(64) ALD(64) TLD(64) HeaderTag(16)      |
/// |  Configuration unique ID(16) (Attestation)                  |
/// |       Optional, defaults to 0                               |
/// |  Reserved(256)                                              |
/// |  User Data(512) (reserved)                                  |
/// |  Customer Public Key (160) generated for each request       |
/// |  N Keyslots(80 each)                                        |
/// |  Secret header (Secret dependent)                           |
/// |     ---------------------------------------------------     |
/// |  Secret to add (Secret type dependent)(may be 0 bytes)      | Encrypted
/// |  Extension secret(32) Optional, defaults to 0               | Encrypted
/// |     ---------------------------------------------------     |
/// |                   AES GCM Tag (16)                          |
/// |_____________________________________________________________|
/// ```
#[derive(Debug)]
pub struct AddSecretRequest {
    version: AddSecretVersion,
    aad: ReqAuthDataVersion,
    keyslots: Vec<Keyslot>,
    conf: ReqConfData,
    user_data: UserData,
}
static_assert!(AddSecretRequest::USER_DATA_OFFS == 0x218);
static_assert!(
    AddSecretRequest::USER_DATA_OFFS == size_of::<RequestHdr>() + size_of::<ReqAuthDataV2>()
);

impl AddSecretRequest {
    /// Offset of the user-data in the add-secret request in bytes
    pub(super) const USER_DATA_OFFS: usize = size_of::<RequestHdr>() + size_of::<ReqAuthDataV1>();

    /// Create a new add-secret request.
    ///
    /// The request has no extension secret, no configuration UID, no host-keys,
    /// and no user data
    pub fn new(
        version: AddSecretVersion,
        secret: GuestSecret,
        boot_tags: BootHdrTags,
        flags: AddSecretFlags,
    ) -> Result<Self> {
        let conf = ReqConfData {
            extension_secret: Confidential::new([0; 32]),
            secret,
        };
        Ok(Self {
            aad: ReqAuthDataVersion::new(version, boot_tags, flags, &conf.secret.auth())?,
            conf,
            keyslots: vec![],
            version,
            user_data: UserData::Null,
        })
    }

    /// Sets the Configuration Unique Id of this [`AddSecretRequest`].
    pub fn set_cuid(&mut self, cuid: ConfigUid) {
        self.aad.set_cuid(cuid);
    }

    /// Sets the extension secret of this [`AddSecretRequest`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the key derivation fails for a [`ExtSecret::Derived`].
    pub fn set_ext_secret(&mut self, ext_secret: ExtSecret) -> Result<()> {
        const DER_EXT_SECRET_INFO: &[u8] = "IBM Z Ultravisor Add-Secret".as_bytes();
        self.conf.extension_secret = match ext_secret {
            ExtSecret::Simple(s) => s,
            ExtSecret::Derived(cck) => hkdf_rfc_5869(
                Md::sha512(),
                cck.value(),
                self.aad.boot_tags().tag(),
                DER_EXT_SECRET_INFO,
            )?
            .into(),
        };
        Ok(())
    }

    /// Returns a reference to the guest secret of this [`AddSecretRequest`].
    pub fn guest_secret(&self) -> &GuestSecret {
        &self.conf.secret
    }

    /// Add user-data to the Add-Secret request
    ///
    /// (Signed) user-data is a non-architectual feature. It allows to add arbitrary
    /// data (message) to the request, that is signed optionally with an user defined key.
    /// Allowed keys are:
    /// - no key (up to 512 bytes of message)
    /// - EC SECP521R1 (up to 256 byte message)
    /// - RSA 2048 bit (up to 256 byte message)
    /// - RSA 3072 bit (up to 128 byte message)
    ///
    /// The signature can be verified during the verification of the secret-request  on the target
    /// machine.
    pub fn set_user_data<T: Into<Vec<u8>>>(
        &mut self,
        msg: T,
        skey: Option<PKey<Private>>,
    ) -> Result<()> {
        self.user_data = UserData::new(skey, msg.into())?;
        Ok(())
    }

    /// Compiles the authenticated area of this request
    fn aad(&self, ctx: &ReqEncrCtx, conf_len: usize) -> Result<Vec<u8>> {
        let cust_pub_key = ctx.key_coords()?;
        let secr_auth = self.conf.secret.auth();
        let user_data = self.user_data.data();
        let mut aad: Vec<Aad> = Vec::with_capacity(5 + self.keyslots.len());
        aad.push(Aad::Plain(self.aad.as_bytes()));
        if let Some(data) = user_data.0 {
            aad.push(Aad::Plain(data));
        }
        if let Some(data) = &user_data.1 {
            aad.push(Aad::Plain(data));
        }
        aad.push(Aad::Plain(cust_pub_key.as_ref()));
        self.keyslots.iter().for_each(|k| aad.push(Aad::Ks(k)));
        // write secret header (1) only for v1
        match self.version {
            AddSecretVersion::One => aad.push(Aad::Plain(secr_auth.get(AddSecretVersion::One))),
            AddSecretVersion::Two => {}
            #[cfg(any(debug_assertions, test))]
            _ => return Err(Error::UnsupportedAddSecretVersion(self.version as u32)),
        }

        ctx.build_aad(self.version.into(), &aad, conf_len, self.user_data.magic())
    }

    #[doc(hidden)]
    #[cfg(any(debug_assertions, test))]
    pub fn aad_and_conf(&self, ctx: &ReqEncrCtx) -> Result<(Vec<u8>, Vec<u8>)> {
        let conf = self.conf.to_bytes();
        let aad = self.aad(ctx, conf.value().len())?;
        Ok((aad, conf.value().to_owned()))
    }

    #[doc(hidden)]
    #[cfg(any(debug_assertions, test))]
    pub fn no_encrypt(&self, ctx: &ReqEncrCtx) -> Result<Vec<u8>> {
        let (mut res, mut conf) = self.aad_and_conf(ctx)?;
        res.append(&mut conf);
        res.append(&mut vec![0x24; 32]);
        Ok(res)
    }

    /// Encrypts data, sign request with user-provided signing key, insert signature into aad,
    /// calculate request tag
    fn encrypt_with_signed_user_data(&self, ctx: &ReqEncrCtx) -> Result<Vec<u8>> {
        // encrypt data w/o aead
        let conf = self.conf.to_bytes();
        let aad = self.aad(ctx, conf.value().len())?;
        let AeadEncryptionResult {
            mut buf,
            aad_range,
            encr_range,
            ..
        } = ctx.encrypt_aead(&aad, conf.value())?;

        drop(aad);

        // sign aad+encrypted data (w/o tag) with user signning key
        // add signature to authenticated data starting with USER_DATA_OFFS
        self.user_data.sign(
            &mut buf[aad_range.start..encr_range.end],
            Self::USER_DATA_OFFS,
        )?;

        // encrypt again with signed data
        buf[encr_range.clone()].copy_from_slice(conf.value());
        ctx.encrypt_aead(&buf[aad_range], &buf[encr_range])
            .map(|res| res.into_buf())
    }

    /// Get a copy of the secret ID if any
    pub fn bin_id(asrcb: &[u8]) -> Result<Option<SecretId>> {
        AddSecretMagic::try_from_bytes(asrcb)?;
        BinReqValues::get(asrcb)
            .map(|req| req.req_dep_aad::<ListableSecretHdr>().map(|a| a.id.clone()))
    }

    /// Get a copy of the add secret request tag
    pub fn bin_tag(asrcb: &[u8]) -> Result<Vec<u8>> {
        AddSecretMagic::try_from_bytes(asrcb)?;
        BinReqValues::get(asrcb).map(|v| v.tag().to_vec())
    }
}

impl Request for AddSecretRequest {
    fn encrypt(&self, ctx: &ReqEncrCtx) -> Result<Vec<u8>> {
        match self.user_data {
            UserData::Null | UserData::Unsigned(_) => {
                let conf = self.conf.to_bytes();
                let aad = self.aad(ctx, conf.value().len())?;
                ctx.encrypt_aead(&aad, conf.value())
                    .map(|res| res.into_buf())
            }
            _ => self.encrypt_with_signed_user_data(ctx),
        }
    }

    fn add_hostkey(&mut self, hostkey: HostKey) -> Result<()> {
        match self.version {
            AddSecretVersion::One if !hostkey.is_hybrid() => Ok(()),
            AddSecretVersion::Two if hostkey.is_hybrid() => Ok(()),
            AddSecretVersion::One => Err(Error::InvalidHkd(
                "Add classical hostkey to a v1 attestation request".to_string(),
            )),
            AddSecretVersion::Two => Err(Error::InvalidHkd(
                "Add hybrid key to a v2 attetstation request".to_string(),
            )),
            #[cfg(any(debug_assertions, test))]
            AddSecretVersion::Inv => panic!("Invalid version for production use"),
        }?;
        self.keyslots.push(Keyslot::new(hostkey));
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::request::SeHdrVersion;

    #[test]
    fn add_secret_version_v1() {
        // Test V1 version constant
        assert_eq!(AddSecretVersion::One as u32, 0x0100);
    }

    #[test]
    fn add_secret_version_v2() {
        // Test V2 version constant
        assert_eq!(AddSecretVersion::Two as u32, 0x0200);
    }

    #[test]
    fn add_secret_version_conversion_v1() {
        // Test conversion from SeHdrVersion to AddSecretVersion for V1
        let v1: AddSecretVersion = SeHdrVersion::One.into();
        assert_eq!(v1, AddSecretVersion::One);
    }

    #[test]
    fn add_secret_version_conversion_v2() {
        // Test conversion from SeHdrVersion to AddSecretVersion for V2
        let v2: AddSecretVersion = SeHdrVersion::Two.into();
        assert_eq!(v2, AddSecretVersion::Two);
    }

    #[test]
    fn add_secret_version_into_request_version() {
        // Test conversion from AddSecretVersion to RequestVersion
        let v1: RequestVersion = AddSecretVersion::One.into();
        assert_eq!(v1, 0x0100);

        let v2: RequestVersion = AddSecretVersion::Two.into();
        assert_eq!(v2, 0x0200);
    }

    #[test]
    fn add_secret_flags_default() {
        // Test default flags have no bits set
        let flags = AddSecretFlags::default();
        let uv_flags: UvFlags = flags.into();

        // Default should have all bits cleared
        assert_eq!(uv_flags.as_bytes(), &[0u8; 8]);
    }

    #[test]
    fn add_secret_flags_disable_dump() {
        // Test disable dump flag sets bit 0
        let mut flags = AddSecretFlags::default();
        flags.set_disable_dump();

        let uv_flags: UvFlags = flags.into();

        // Bit 0 should be set, so bytes should not be all zeros
        assert_ne!(uv_flags.as_bytes(), &[0u8; 8]);
    }

    #[test]
    fn req_auth_data_size() {
        // Test ReqAuthData size constant
        use std::mem::size_of;

        assert_eq!(size_of::<ReqAuthDataV1>(), 0x1e8);
    }

    #[test]
    #[cfg(any(debug_assertions, test))]
    fn add_secret_version_inv_for_testing() {
        // Test that invalid version exists for testing
        assert_eq!(AddSecretVersion::Inv as u32, 0);
        assert_ne!(AddSecretVersion::Inv, AddSecretVersion::One);
        assert_ne!(AddSecretVersion::Inv, AddSecretVersion::Two);
    }
}
