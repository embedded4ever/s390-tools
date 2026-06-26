// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.

// DO NOT USE ANY OF THESE ITEMS IN PRODUCTION CODE
// USED FOR INTERNAL UNIT AND FVT TESTING ONLY!!!
use std::ffi::c_void;
use std::fs;
use std::mem::{size_of, ManuallyDrop};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;

use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::x509::{X509Crl, X509};

/// TEST ONLY! Loads the specified asset into the binary at compile time.
///
/// For testing-assets only!
/// The asset must be present at `{crate}/test/assets/{file}`
#[doc(hidden)]
#[macro_export]
macro_rules! get_test_asset {
    ($file:expr) => {
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets/", $file))
    };
}

pub fn get_cert_asset_path<P: AsRef<Path>>(path: P) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("assets");
    p.push("cert");
    p.push(path);
    println!("CERT path: {}", p.to_str().unwrap());
    p
}

/// TEST ONLY! Load an cert
///
/// panic on errors
pub fn get_cert_asset<P: AsRef<Path>>(path: P) -> Vec<u8> {
    let p = get_cert_asset_path(path);
    fs::read(p).unwrap()
}

/// TEST ONLY! Load cert found in the asset path
///
/// panic on errors
pub fn load_gen_cert<P: AsRef<Path>>(asset_path: P) -> X509 {
    let buf = get_cert_asset(asset_path);
    let mut cert = X509::from_der(&buf)
        .map(|crt| vec![crt])
        .or_else(|_| X509::stack_from_pem(&buf))
        .unwrap();
    assert_eq!(cert.len(), 1);
    cert.pop().unwrap()
}

/// TEST ONLY! Load the CRL found in the asset path
///
/// panic on errors
pub fn load_gen_crl<P: AsRef<Path>>(asset_path: P) -> X509Crl {
    let buf = get_cert_asset(asset_path);

    X509Crl::from_der(&buf)
        .or_else(|_| X509Crl::from_pem(&buf))
        .unwrap()
}

/// TEST ONLY! Get a fixed private/public pair and a fixed host-key document
///
/// Intended for TESTING only. All parts of the key including the private key are checked in git and
/// visible for the public
pub fn get_test_key_and_cert() -> (PKey<Private>, X509) {
    let pub_key = get_test_asset!("keys/public_cust.bin");
    let priv_key = get_test_asset!("keys/private_cust.bin");
    let host_key = get_test_asset!("keys/host.pem.crt");

    assert_eq!(pub_key.len(), 160);
    assert_eq!(priv_key.len(), 80);

    let cust_key = get_keypair(pub_key, priv_key).unwrap();
    let host_key = X509::from_pem(host_key).unwrap();

    (cust_key, host_key)
}

pub fn get_test_key_and_cert_hybrid() -> (PKey<Private>, X509, X509) {
    let pub_key = get_test_asset!("keys/public_cust.bin");
    let priv_key = get_test_asset!("keys/private_cust.bin");
    let host_key = get_test_asset!("keys/host.ec.crt");
    let host_keys = get_test_asset!("keys/host.hybrid.crt");

    assert_eq!(pub_key.len(), 160);
    assert_eq!(priv_key.len(), 80);

    let cust_key = get_keypair(pub_key, priv_key).unwrap();
    let host_key1 = X509::from_pem(host_key).unwrap();
    let host_keys = X509::stack_from_pem(host_keys).unwrap();
    assert_eq!(host_keys.len(), 2);

    println!("host_key1 = {host_key1:?}");
    println!("host_keys[0] = {:?}", host_keys[0]);
    println!("host_keys[1] = {:?}", host_keys[1]);

    (cust_key, host_key1, host_keys[1].clone())
}

/// TEST ONLY! Get a fixed private/public pair and a fixed public key
///
/// Intended for TESTING only. All parts of the key including the private key are checked in git and
/// visible for the public
pub fn get_test_keys() -> (PKey<Private>, PKey<Public>) {
    let (cust_key, host) = get_test_key_and_cert();
    (cust_key, host.public_key().unwrap())
}

pub fn get_test_keys_hybrid() -> (PKey<Private>, PKey<Public>, PKey<Public>) {
    let (cust_key, host_key_1, host_key_2) = get_test_key_and_cert_hybrid();
    (
        cust_key,
        host_key_1.public_key().unwrap(),
        host_key_2.public_key().unwrap(),
    )
}

fn read_ecdh_pubkey(coords: &[u8]) -> Result<PKey<Public>, ErrorStack> {
    assert!(coords.len() == 160);
    let x = BigNum::from_slice(&coords[..80])?;
    let y = BigNum::from_slice(&coords[80..])?;
    let group = EcGroup::from_curve_name(Nid::SECP521R1)?;

    let key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)?;
    PKey::from_ec_key(key)
}

fn get_keypair(pub_coords: &[u8], priv_num: &[u8]) -> Result<PKey<Private>, ErrorStack> {
    assert!(pub_coords.len() == 160);
    assert!(priv_num.len() == 80);
    let pub_key = read_ecdh_pubkey(pub_coords)?;
    let pub_key = pub_key.ec_key()?;
    let pub_key = pub_key.public_key();
    let priv_key = BigNum::from_slice(priv_num)?;
    let group = EcGroup::from_curve_name(Nid::SECP521R1)?;

    let key = EcKey::from_private_components(&group, &priv_key, pub_key)?;
    key.check_key()?;
    PKey::from_ec_key(key)
}

// To regenerate these bindings, run:
// bindgen bindgen_wrapper.h -o bindgen_output.rs \
//   --allowlist-function "RAND_get0_public" \
//   --allowlist-function "RAND_get0_private" --allowlist-function "EVP_RAND_fetch" \
//   --allowlist-function "EVP_RAND_free" --allowlist-function "EVP_RAND_CTX_new" \
//   --allowlist-function "EVP_RAND_CTX_free" --allowlist-function "EVP_RAND_CTX_up_ref" \
//   --allowlist-function "EVP_RAND_instantiate" --allowlist-function "RAND_set0_public" \
//   --allowlist-function "RAND_set0_private" --allowlist-type "OSSL_PARAM"
// where bindgen_wrapper.h contains:
//   #include <openssl/provider.h>
//   #include <openssl/rand.h>
//   #include <openssl/evp.h>
//   #include <openssl/params.h>
mod ffi {
    use std::ffi::{c_char, c_int, c_uchar, c_uint, c_void};

    #[repr(C)]
    pub struct OsslParam {
        pub key: *const c_char,
        pub data_type: c_uint,
        pub data: *mut c_void,
        pub data_size: usize,
        pub return_size: usize,
    }

    pub enum OsslLibCtx {}
    pub enum OsslProvider {}
    pub enum EvpRand {}
    pub enum EvpRandCtx {}

    unsafe extern "C" {
        pub fn RAND_get0_public(ctx: *mut OsslLibCtx) -> *mut EvpRandCtx;
        pub fn RAND_get0_private(ctx: *mut OsslLibCtx) -> *mut EvpRandCtx;
        pub fn EVP_RAND_fetch(
            libctx: *mut OsslLibCtx,
            algorithm: *const c_char,
            properties: *const c_char,
        ) -> *mut EvpRand;
        pub fn EVP_RAND_free(rand: *mut EvpRand);
        pub fn EVP_RAND_CTX_new(rand: *mut EvpRand, parent: *mut EvpRandCtx) -> *mut EvpRandCtx;
        pub fn EVP_RAND_CTX_free(ctx: *mut EvpRandCtx);
        pub fn EVP_RAND_CTX_up_ref(ctx: *mut EvpRandCtx) -> c_int;
        pub fn EVP_RAND_instantiate(
            ctx: *mut EvpRandCtx,
            strength: c_uint,
            prediction_resistance: c_int,
            pstr: *const c_uchar,
            pstr_len: usize,
            params: *const OsslParam,
        ) -> c_int;
        pub fn RAND_set0_public(ctx: *mut OsslLibCtx, rand: *mut EvpRandCtx) -> c_int;
        pub fn RAND_set0_private(ctx: *mut OsslLibCtx, rand: *mut EvpRandCtx) -> c_int;
    }
}

// Constants for OSSL_PARAM construction
const OSSL_PARAM_OCTET_STRING: u32 = 5;
const OSSL_PARAM_UNSIGNED_INTEGER: u32 = 2;
const OSSL_PARAM_END: u32 = 0;

fn ossl_param_end() -> ffi::OsslParam {
    ffi::OsslParam {
        key: std::ptr::null(),
        data_type: OSSL_PARAM_END,
        data: std::ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    }
}

fn ossl_param_octet_string(name: &'static [u8], data: &mut [u8]) -> ffi::OsslParam {
    // SAFETY: Constructing OSSL_PARAM for octet string.
    // - name is a static null-terminated C string, valid for 'static
    // - data is a valid mutable slice, pointer remains valid during param usage
    // - Pointer casts are safe as they preserve alignment and validity
    ffi::OsslParam {
        key: name.as_ptr().cast(),
        data_type: OSSL_PARAM_OCTET_STRING,
        data: data.as_mut_ptr().cast(),
        data_size: data.len(),
        return_size: data.len(),
    }
}

fn ossl_param_uint(name: &'static [u8], value: &mut u32) -> ffi::OsslParam {
    // SAFETY: Constructing OSSL_PARAM for unsigned integer.
    // - name is a static null-terminated C string, valid for 'static
    // - value is a valid mutable reference, pointer remains valid during param usage
    // - Pointer cast to c_void is safe as it preserves alignment and validity
    ffi::OsslParam {
        key: name.as_ptr().cast(),
        data_type: OSSL_PARAM_UNSIGNED_INTEGER,
        data: (value as *mut u32).cast::<c_void>(),
        data_size: size_of::<u32>(),
        return_size: size_of::<u32>(),
    }
}

#[derive(Debug)]
struct FetchedRand(NonNull<ffi::EvpRand>);

impl FetchedRand {
    const TEST_RAND_NAME: &'static [u8] = b"TEST-RAND\0";

    fn fetch_test_rand() -> Result<Self, ErrorStack> {
        // SAFETY: Calling OpenSSL C API with valid parameters.
        // - null_mut() is valid for optional OSSL_LIB_CTX parameter
        // - Self::TEST_RAND_NAME is a valid null-terminated C string
        // - null() is valid for optional properties parameter
        // - Returns null on error, which we handle via NonNull::new
        let rand = unsafe {
            ffi::EVP_RAND_fetch(
                std::ptr::null_mut(),
                Self::TEST_RAND_NAME.as_ptr().cast(),
                std::ptr::null(),
            )
        };
        NonNull::new(rand).map(Self).ok_or_else(ErrorStack::get)
    }

    fn as_ptr(&self) -> *mut ffi::EvpRand {
        self.0.as_ptr()
    }
}

impl Drop for FetchedRand {
    fn drop(&mut self) {
        // SAFETY: self.0 is a valid non-null EVP_RAND pointer that we own.
        // This is the only place we call free, preventing double-free.
        unsafe {
            ffi::EVP_RAND_free(self.0.as_ptr());
        }
    }
}

#[derive(Debug)]
struct RandCtx(NonNull<ffi::EvpRandCtx>);

impl RandCtx {
    fn new(rand: &FetchedRand) -> Result<Self, ErrorStack> {
        // SAFETY: Calling OpenSSL C API with valid parameters.
        // - rand.as_ptr() is a valid non-null EVP_RAND pointer
        // - null_mut() is valid for optional parent parameter
        // - Returns null on error, which we handle via NonNull::new
        let ctx = unsafe { ffi::EVP_RAND_CTX_new(rand.as_ptr(), std::ptr::null_mut()) };
        NonNull::new(ctx).map(Self).ok_or_else(ErrorStack::get)
    }

    fn up_ref(ptr: *mut ffi::EvpRandCtx) -> Result<Self, ErrorStack> {
        let ptr = NonNull::new(ptr).ok_or_else(ErrorStack::get)?;
        // SAFETY: ptr is a valid non-null EVP_RAND_CTX pointer.
        // EVP_RAND_CTX_up_ref increments the reference count.
        // Returns 1 on success, 0 on failure.
        let rc = unsafe { ffi::EVP_RAND_CTX_up_ref(ptr.as_ptr()) };
        if rc == 1 {
            Ok(Self(ptr))
        } else {
            Err(ErrorStack::get())
        }
    }

    fn current_public() -> Result<Option<Self>, ErrorStack> {
        // SAFETY: RAND_get0_public returns a borrowed pointer (no ownership transfer).
        // Returns null if no public RNG is set, which we handle.
        let ptr = unsafe { ffi::RAND_get0_public(std::ptr::null_mut()) };
        if ptr.is_null() {
            Ok(None)
        } else {
            Self::up_ref(ptr).map(Some)
        }
    }

    fn current_private() -> Result<Option<Self>, ErrorStack> {
        // SAFETY: RAND_get0_private returns a borrowed pointer (no ownership transfer).
        // Returns null if no private RNG is set, which we handle.
        let ptr = unsafe { ffi::RAND_get0_private(std::ptr::null_mut()) };
        if ptr.is_null() {
            Ok(None)
        } else {
            Self::up_ref(ptr).map(Some)
        }
    }

    fn as_ptr(&self) -> *mut ffi::EvpRandCtx {
        self.0.as_ptr()
    }

    fn instantiate_test_rand(&self, entropy: &[u8], nonce: &[u8]) -> Result<(), ErrorStack> {
        // See https://docs.openssl.org/3.1/man7/EVP_RAND-TEST-RAND/#description
        // for the available parameters.
        const TEST_ENTROPY_PARAM: &[u8] = b"test_entropy\0";
        const TEST_NONCE_PARAM: &[u8] = b"test_nonce\0";
        const STRENGTH_PARAM: &[u8] = b"strength\0";

        let mut entropy = entropy.to_vec();
        let mut nonce = nonce.to_vec();
        let mut strength = 256u32;
        let params = [
            ossl_param_uint(STRENGTH_PARAM, &mut strength),
            ossl_param_octet_string(TEST_ENTROPY_PARAM, &mut entropy),
            ossl_param_octet_string(TEST_NONCE_PARAM, &mut nonce),
            ossl_param_end(),
        ];

        // SAFETY: Calling OpenSSL C API with valid parameters.
        // - self.as_ptr() is a valid non-null EVP_RAND_CTX pointer
        // - strength is a valid u32 value
        // - prediction_resistance=0 is valid
        // - pstr=null and pstr_len=0 indicate no personalization string
        // - params points to a valid array of OSSL_PARAM with proper terminator
        // - All mutable references in params remain valid for the call duration
        let rc = unsafe {
            ffi::EVP_RAND_instantiate(
                self.as_ptr(),
                strength,
                0,
                std::ptr::null(),
                0,
                params.as_ptr(),
            )
        };
        if rc == 1 {
            Ok(())
        } else {
            Err(ErrorStack::get())
        }
    }

    fn install_as_public(self) -> Result<InstalledRandCtx, ErrorStack> {
        // SAFETY: Calling OpenSSL C API to transfer ownership.
        // - self.as_ptr() is a valid non-null EVP_RAND_CTX pointer
        // - RAND_set0_public takes ownership of the context on success (rc==1)
        // - We wrap in ManuallyDrop to prevent double-free since OpenSSL now owns it
        let rc = unsafe { ffi::RAND_set0_public(std::ptr::null_mut(), self.as_ptr()) };
        if rc == 1 {
            Ok(InstalledRandCtx(ManuallyDrop::new(self)))
        } else {
            Err(ErrorStack::get())
        }
    }

    fn install_as_private(self) -> Result<InstalledRandCtx, ErrorStack> {
        // SAFETY: Calling OpenSSL C API to transfer ownership.
        // - self.as_ptr() is a valid non-null EVP_RAND_CTX pointer
        // - RAND_set0_private takes ownership of the context on success (rc==1)
        // - We wrap in ManuallyDrop to prevent double-free since OpenSSL now owns it
        let rc = unsafe { ffi::RAND_set0_private(std::ptr::null_mut(), self.as_ptr()) };
        if rc == 1 {
            Ok(InstalledRandCtx(ManuallyDrop::new(self)))
        } else {
            Err(ErrorStack::get())
        }
    }
}

impl Drop for RandCtx {
    fn drop(&mut self) {
        // SAFETY: self.0 is a valid non-null EVP_RAND_CTX pointer that we own.
        // This is only called when ownership was NOT transferred to OpenSSL.
        // InstalledRandCtx uses ManuallyDrop to prevent this from running after transfer.
        unsafe {
            ffi::EVP_RAND_CTX_free(self.0.as_ptr());
        }
    }
}

#[derive(Debug)]
struct InstalledRandCtx(ManuallyDrop<RandCtx>);

impl Drop for InstalledRandCtx {
    fn drop(&mut self) {
        // SAFETY: Ownership of the EVP_RAND_CTX was transferred to OpenSSL
        // via RAND_set0_public/private, so we must not call EVP_RAND_CTX_free.
        // ManuallyDrop prevents RandCtx::drop from running automatically.
    }
}

#[derive(Debug)]
struct PreviousRandCtx(Option<RandCtx>);

impl PreviousRandCtx {
    fn capture_public() -> Result<Self, ErrorStack> {
        RandCtx::current_public().map(Self)
    }

    fn capture_private() -> Result<Self, ErrorStack> {
        RandCtx::current_private().map(Self)
    }

    fn restore_public(&mut self) {
        let Some(ctx) = self.0.take() else {
            return;
        };
        // SAFETY: Restoring previously captured RNG context.
        // - ctx.as_ptr() is a valid non-null EVP_RAND_CTX pointer
        // - RAND_set0_public takes ownership of the context
        // - We forget ctx to prevent double-free since OpenSSL now owns it
        // - Ignoring return value as restoration is best-effort during cleanup
        let _ = unsafe { ffi::RAND_set0_public(std::ptr::null_mut(), ctx.as_ptr()) };
        std::mem::forget(ctx);
    }

    fn restore_private(&mut self) {
        let Some(ctx) = self.0.take() else {
            return;
        };
        // SAFETY: Restoring previously captured RNG context.
        // - ctx.as_ptr() is a valid non-null EVP_RAND_CTX pointer
        // - RAND_set0_private takes ownership of the context

        // - We forget ctx to prevent double-free since OpenSSL now owns it
        // - Ignoring return value as restoration is best-effort during cleanup
        let _ = unsafe { ffi::RAND_set0_private(std::ptr::null_mut(), ctx.as_ptr()) };
        std::mem::forget(ctx);
    }
}

#[derive(Debug)]
pub struct DeterministicTestRandGuard {
    previous_public: PreviousRandCtx,
    previous_private: PreviousRandCtx,
    _public: InstalledRandCtx,
    _private: InstalledRandCtx,
}

impl DeterministicTestRandGuard {
    /// Install OpenSSL >= 3 TEST-RAND as the thread-local public/private RNG for deterministic
    /// tests.
    ///
    /// The supplied entropy is consumed across generate calls. The nonce is replayed for each
    /// nonce request. Per OpenSSL documentation, the public and private DRBG instances are
    /// thread-local, so each thread can safely install its own deterministic RNG without
    /// affecting other threads.
    ///
    /// # Thread Safety
    ///
    /// From OpenSSL documentation (RAND_get0_primary(3)):
    /// > "The public and private DRBG are thread-local instances, which are used by
    /// > RAND_bytes() and RAND_priv_bytes(), respectively."
    ///
    /// Reference: <https://docs.openssl.org/3.1/man3/RAND_get0_primary/>
    ///
    /// **Note:** RAND_set0_public() and RAND_set0_private() require OpenSSL >= 3.1.
    ///
    /// # Errors
    ///
    /// Returns an OpenSSL error if the TEST-RAND provider cannot be configured.
    pub fn install(entropy: &[u8], nonce: &[u8]) -> Result<Self, ErrorStack> {
        let previous_public = PreviousRandCtx::capture_public()?;
        let previous_private = PreviousRandCtx::capture_private()?;
        let rand = FetchedRand::fetch_test_rand()?;

        let public = RandCtx::new(&rand)?;
        public.instantiate_test_rand(entropy, nonce)?;
        let public = public.install_as_public()?;

        let private = RandCtx::new(&rand)?;
        private.instantiate_test_rand(entropy, nonce)?;
        let private = private.install_as_private()?;

        Ok(Self {
            previous_public,
            previous_private,
            _public: public,
            _private: private,
        })
    }
}

impl Drop for DeterministicTestRandGuard {
    fn drop(&mut self) {
        self.previous_private.restore_private();
        self.previous_public.restore_public();
    }
}
