// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.

use std::fmt::{Display, Formatter};
use std::path::Path;

use log::{error, info};
use openssl::nid::Nid;
use openssl::pkey::{Id, KeyType, PKeyRef, Public};
use openssl::x509::X509;
use pv::misc::{read_certs, read_file};
use pv::request::{HkdVerifier, HostKey, HybridPKey};
use pv::{Error, Result};

use crate::AutoOrExplicit;

/// Host key document version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdVersion {
    /// Version 1 - uses traditional cryptographic keys (1 certificate)
    Classical,
    /// Version 2 - uses hybrid (post-quantum) cryptographic keys (2 certificates)
    Hybrid,
}

impl HkdVersion {
    /// Get the required certificate count for this version
    pub fn cert_count(self) -> usize {
        match self {
            HkdVersion::Classical => 1,
            HkdVersion::Hybrid => 2,
        }
    }
}

impl Display for HkdVersion {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            HkdVersion::Classical => write!(f, "classical"),
            HkdVersion::Hybrid => write!(f, "hybrid"),
        }
    }
}

pub type HkdVersionSelection = AutoOrExplicit<HkdVersion>;

/// Helper struct for loading and verifying host-key documents
pub struct HkdLoader;

impl HkdLoader {
    fn detect_version(path: &Path, certs: &Vec<X509>) -> Result<HkdVersion> {
        info!("Auto-detecting version of the host-key document format");
        Ok(match certs.len() {
            1 => HkdVersion::Classical,
            2 => HkdVersion::Hybrid,
            _ => {
                error!(
                "Invalid host-key document '{}': it contains more than two certificates, which is not supported by any host-key document format.",
                path.display()
            );
                return Err(Error::WrongNumberOfKeys(path.display().to_string()));
            }
        })
    }

    fn validate_version(path: &Path, certs: &Vec<X509>, version: HkdVersion) -> Result<HkdVersion> {
        if certs.len() != version.cert_count() {
            error!(
                "Host-key document '{}' is not a {} host-key document.",
                path.display(),
                version,
            );
            return Err(Error::WrongNumberOfKeys(path.display().to_string()));
        }
        Ok(version)
    }

    fn is_ec_p521_key(key: &PKeyRef<Public>) -> bool {
        if key.id() == Id::EC {
            if let Ok(ec_key) = key.ec_key() {
                let group = ec_key.group();
                if let Some(curve_nid) = group.curve_name() {
                    return curve_nid == Nid::SECP521R1;
                }
            }
        }
        false
    }

    fn is_mlkem1024_key(key: &PKeyRef<Public>) -> bool {
        key.is_a(KeyType::ML_KEM_1024)
    }

    /// Load and verify a host-key document from a file
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The file cannot be read
    /// - The content is not valid PEM or DER format
    /// - The file contains no certificates or wrong number of certificates
    /// - The public key cannot be extracted from the certificate(s)
    /// - The verification fails
    /// - Key types are invalid
    pub fn load_and_verify<P: AsRef<Path>>(
        path: P,
        verifier: &dyn HkdVerifier,
        requested_version: HkdVersionSelection,
    ) -> Result<HostKey> {
        let path = path.as_ref();
        let hk = read_file(path, "host-key document")?;
        let certs = read_certs(&hk).map_err(|source| Error::HkdNotPemOrDer {
            hkd: path.display().to_string(),
            source,
        })?;

        if certs.is_empty() {
            return Err(Error::NoHkdInFile(path.display().to_string()));
        }

        let version = match requested_version {
            HkdVersionSelection::Auto => Self::detect_version(path, &certs)?,
            HkdVersionSelection::Explicit(version) => {
                Self::validate_version(path, &certs, version)?
            }
        };

        info!("Using {version} host-key document format");

        // SAFETY: certs is guaranteed to be non-empty due to the check
        let c1 = certs
            .first()
            .expect("Certificate list validated as non-empty");

        if !Self::is_ec_p521_key(c1.public_key()?.as_ref()) {
            return Err(Error::InvalidHkd(
                "First key must be a EC-p521 key".to_string(),
            ));
        }
        verifier.verify(c1)?;

        match version {
            HkdVersion::Classical => Ok(HostKey::V1(c1.public_key()?)),
            HkdVersion::Hybrid => {
                let c2 = &certs
                    .get(1)
                    .expect("Certificate list length was already checked");
                if !Self::is_mlkem1024_key(c2.public_key()?.as_ref()) {
                    return Err(Error::InvalidHkd(
                        "Second key must be a ML-KEM 1024 key".to_string(),
                    ));
                }
                verifier.verify(c2)?;
                Ok(HostKey::V2(HybridPKey::new(
                    c1.public_key()?,
                    c2.public_key()?,
                )?))
            }
        }
    }
}
