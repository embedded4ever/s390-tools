// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.

//! Host key types for UV requests

use openssl::nid::Nid;
use openssl::pkey::{KeyType, PKey, PKeyRef, Public};

use crate::crypto::{validate_ec_key, validate_key_type};
pub use crate::error::Result;

/// Hybrid public key (ECDH and ML-KEM)
#[derive(Clone, Debug)]
pub struct HybridPKey {
    /// ECDH public key
    pub(super) ec_key: PKey<Public>,

    /// ML-KEM public key
    pub(super) mlkem_key: PKey<Public>,
}

impl HybridPKey {
    /// Creates a new hybrid public key with validation.
    ///
    /// # Parameters
    /// - `ec_key`: ECDH public key (must be SECP521R1)
    /// - `mlkem_key`: ML-KEM public key (must be ML-KEM-1024)
    ///
    /// # Errors
    /// Returns an error if:
    /// - EC key is not SECP521R1 curve
    /// - ML-KEM key is not ML-KEM-1024
    pub fn new(ec_key: PKey<Public>, mlkem_key: PKey<Public>) -> Result<Self> {
        validate_ec_key(&ec_key, "ECDH key", Nid::SECP521R1)?;
        validate_key_type(&mlkem_key, "ML-KEM key", KeyType::ML_KEM_1024)?;

        Ok(Self { ec_key, mlkem_key })
    }

    /// Returns a reference to the EC key
    pub fn ec_key(&self) -> &PKeyRef<Public> {
        &self.ec_key
    }

    /// Returns a reference to the ML-KEM key
    pub fn mlkem_key(&self) -> &PKeyRef<Public> {
        &self.mlkem_key
    }
}

impl AsRef<HybridPKey> for HybridPKey {
    fn as_ref(&self) -> &HybridPKey {
        self
    }
}

/// Versioned host keys container
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum HostKey {
    /// ECDH public key
    V1(PKey<Public>),

    /// Hybrid public key (ECDH and ML-KEM)
    V2(HybridPKey),
}

impl HostKey {
    /// Return the ECDH public key
    pub fn ec_key(&self) -> Option<&PKeyRef<Public>> {
        Some(match self {
            HostKey::V1(ec_key) => ec_key,
            HostKey::V2(hybrid) => hybrid.ec_key(),
        })
    }

    /// Return the ML-KEM public key
    pub fn mlkem_key(&self) -> Option<&PKeyRef<Public>> {
        match self {
            HostKey::V1(_) => None,
            HostKey::V2(hybrid) => Some(hybrid.mlkem_key()),
        }
    }

    /// Test if the hostkey is hybrid
    #[must_use]
    pub fn is_hybrid(&self) -> bool {
        matches!(self, HostKey::V2(_))
    }
}

impl AsRef<HostKey> for HostKey {
    fn as_ref(&self) -> &HostKey {
        self
    }
}

#[cfg(test)]
mod tests {
    use openssl::ec::{EcGroup, EcKey};
    use openssl::pkey::Private;

    use super::*;
    use crate::openssl_extensions::generate_ml_kem;
    use crate::test_utils::get_test_key_and_cert_hybrid;
    use crate::Error;

    fn to_public_key(key: &PKey<Private>) -> Result<PKey<Public>> {
        let der = key.public_key_to_der()?;
        Ok(PKey::public_key_from_der(&der)?)
    }

    #[test]
    fn test_hostkey_v1_variant() {
        let (_, ec_key) = crate::test_utils::get_test_key_and_cert();
        let hostkey = HostKey::V1(ec_key.public_key().unwrap());

        assert!(!hostkey.is_hybrid(), "V1 HostKey should not be hybrid");
        assert!(matches!(hostkey, HostKey::V1(_)));
    }

    #[test]
    fn test_hostkey_v2_variant() {
        let (_, ec_key, mlkem_key) = get_test_key_and_cert_hybrid();
        let hybrid = HybridPKey::new(
            ec_key.public_key().unwrap(),
            mlkem_key.public_key().unwrap(),
        )
        .unwrap();
        let hostkey = HostKey::V2(hybrid);

        assert!(hostkey.is_hybrid(), "V2 HostKey should be hybrid");
        assert!(matches!(hostkey, HostKey::V2(_)));
    }

    #[test]
    fn test_hostkey_ec_key_access() {
        let (_, ec_key, mlkem_key) = get_test_key_and_cert_hybrid();
        let hybrid = HybridPKey::new(
            ec_key.public_key().unwrap(),
            mlkem_key.public_key().unwrap(),
        )
        .unwrap();

        let v1_key = HostKey::V1(ec_key.public_key().unwrap());
        let v2_key = HostKey::V2(hybrid);

        assert!(v1_key.ec_key().unwrap().public_key_to_der().is_ok());
        assert!(v2_key.ec_key().unwrap().public_key_to_der().is_ok());
    }

    #[test]
    fn test_hostkey_v2_mlkem_key_access() {
        let (_, ec_key, mlkem_key) = get_test_key_and_cert_hybrid();
        let hybrid = HybridPKey::new(
            ec_key.public_key().unwrap(),
            mlkem_key.public_key().unwrap(),
        )
        .unwrap();
        let hostkey = HostKey::V2(hybrid);

        assert!(hostkey.mlkem_key().unwrap().public_key_to_der().is_ok());
    }

    #[test]
    fn test_hostkey_v1_has_no_mlkem_key() {
        let (_, ec_key) = crate::test_utils::get_test_key_and_cert();
        let hostkey = HostKey::V1(ec_key.public_key().unwrap());

        assert!(hostkey.mlkem_key().is_none());
    }

    #[test]
    fn test_hybrid_public_key_structure() {
        let (_, ec_key, mlkem_key) = get_test_key_and_cert_hybrid();
        let hybrid = HybridPKey::new(
            ec_key.public_key().unwrap(),
            mlkem_key.public_key().unwrap(),
        )
        .unwrap();

        // Verify both components are present and valid
        assert!(!hybrid.ec_key().public_key_to_der().unwrap().is_empty());
        assert!(!hybrid.mlkem_key().public_key_to_der().unwrap().is_empty());
    }

    #[test]
    fn test_hybrid_pkey_invalid_ec_curve() {
        // Generate a P-256 key instead of P-521
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let wrong_ec_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();

        let (_, _, mlkem_key) = get_test_key_and_cert_hybrid();

        let result = HybridPKey::new(
            to_public_key(&wrong_ec_key).unwrap(),
            mlkem_key.public_key().unwrap(),
        );
        assert!(result.is_err(), "Should reject EC key with wrong curve");

        if let Err(Error::RetrInvKey {
            what,
            kind,
            value,
            exp,
        }) = result
        {
            assert_eq!(what, "curve");
            assert_eq!(kind, "ECDH key");
            assert_eq!(value, "prime256v1");
            assert_eq!(exp, "secp521r1");
        } else {
            panic!("Expected RetrInvKey error for wrong curve");
        }
    }

    #[test]
    fn test_hybrid_pkey_invalid_mlkem_type() {
        let (_, ec_key, _) = get_test_key_and_cert_hybrid();

        // Generate ML-KEM-512 instead of ML-KEM-1024
        let wrong_mlkem_key = generate_ml_kem(KeyType::ML_KEM_512).unwrap();

        let result = HybridPKey::new(
            ec_key.public_key().unwrap(),
            to_public_key(&wrong_mlkem_key).unwrap(),
        );
        assert!(result.is_err(), "Should reject ML-KEM key with wrong type");

        if let Err(Error::RetrInvKey {
            what,
            kind,
            value,
            exp,
        }) = result
        {
            assert_eq!(what, "key type");
            assert_eq!(kind, "ML-KEM key");
            assert_eq!(value, "ML-KEM-512");
            assert_eq!(exp, "ML-KEM-1024");
        } else {
            panic!("Expected RetrInvKey error for wrong ML-KEM type");
        }
    }

    #[test]
    fn test_hybrid_pkey_clone() {
        let (_, ec_key, mlkem_key) = get_test_key_and_cert_hybrid();
        let hybrid = HybridPKey::new(
            ec_key.public_key().unwrap(),
            mlkem_key.public_key().unwrap(),
        )
        .unwrap();

        let cloned = hybrid.clone();

        // Verify both original and clone have valid keys
        assert!(!hybrid.ec_key().public_key_to_der().unwrap().is_empty());
        assert!(!hybrid.mlkem_key().public_key_to_der().unwrap().is_empty());
        assert!(!cloned.ec_key().public_key_to_der().unwrap().is_empty());
        assert!(!cloned.mlkem_key().public_key_to_der().unwrap().is_empty());

        // Verify the keys are equivalent
        assert_eq!(
            hybrid.ec_key().public_key_to_der().unwrap(),
            cloned.ec_key().public_key_to_der().unwrap()
        );
        assert_eq!(
            hybrid.mlkem_key().public_key_to_der().unwrap(),
            cloned.mlkem_key().public_key_to_der().unwrap()
        );
    }

    #[test]
    fn test_hostkey_clone() {
        let (_, ec_key, mlkem_key) = get_test_key_and_cert_hybrid();
        let hybrid = HybridPKey::new(
            ec_key.public_key().unwrap(),
            mlkem_key.public_key().unwrap(),
        )
        .unwrap();

        // Test cloning V1
        let v1_key = HostKey::V1(ec_key.public_key().unwrap());
        let v1_cloned = v1_key.clone();
        assert!(!v1_cloned.is_hybrid());
        assert_eq!(
            v1_key.ec_key().unwrap().public_key_to_der().unwrap(),
            v1_cloned.ec_key().unwrap().public_key_to_der().unwrap()
        );

        // Test cloning V2
        let v2_key = HostKey::V2(hybrid);
        let v2_cloned = v2_key.clone();
        assert!(v2_cloned.is_hybrid());
        assert_eq!(
            v2_key.ec_key().unwrap().public_key_to_der().unwrap(),
            v2_cloned.ec_key().unwrap().public_key_to_der().unwrap()
        );
        assert_eq!(
            v2_key.mlkem_key().unwrap().public_key_to_der().unwrap(),
            v2_cloned.mlkem_key().unwrap().public_key_to_der().unwrap()
        );
    }

    #[test]
    fn test_hybrid_pkey_as_ref() {
        let (_, ec_key, mlkem_key) = get_test_key_and_cert_hybrid();
        let hybrid = HybridPKey::new(
            ec_key.public_key().unwrap(),
            mlkem_key.public_key().unwrap(),
        )
        .unwrap();

        let hybrid_ref: &HybridPKey = hybrid.as_ref();
        assert!(!hybrid_ref.ec_key().public_key_to_der().unwrap().is_empty());
        assert!(!hybrid_ref
            .mlkem_key()
            .public_key_to_der()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn test_hostkey_as_ref() {
        let (_, ec_key, mlkem_key) = get_test_key_and_cert_hybrid();
        let hybrid = HybridPKey::new(
            ec_key.public_key().unwrap(),
            mlkem_key.public_key().unwrap(),
        )
        .unwrap();

        let v1_key = HostKey::V1(ec_key.public_key().unwrap());
        let v1_ref: &HostKey = v1_key.as_ref();
        assert!(!v1_ref.is_hybrid());

        let v2_key = HostKey::V2(hybrid);
        let v2_ref: &HostKey = v2_key.as_ref();
        assert!(v2_ref.is_hybrid());
    }
}
