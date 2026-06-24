use std::path::Path;

// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023
use log::{error, info};
use openssl::error::ErrorStack;
use openssl::x509::{X509Crl, X509};
use pv_core::misc::read_file;

use crate::req::{HostKey, HybridPKey};
use crate::{Error, Result};

/// Read all CRLs from the buffer and parse them into a vector.
///
/// # Errors
///
/// This function will return an error if the underlying OpenSSL implementation cannot parse `buf`
/// as `DER` or `PEM`.
pub fn read_crls<T: AsRef<[u8]>>(buf: T) -> Result<Vec<X509Crl>> {
    use crate::openssl_extensions::StackableX509Crl;
    X509Crl::from_der(buf.as_ref())
        .map(|crl| vec![crl])
        .or_else(|_| StackableX509Crl::stack_from_pem(buf.as_ref()))
        .map_err(Error::Crypto)
}

/// Read all certificates from the buffer and parse them into a vector.
///
/// # Errors
///
/// This function will return an error if the underlying OpenSSL implementation cannot parse `buf`
pub fn read_certs<T: AsRef<[u8]>>(buf: T) -> Result<Vec<X509>, ErrorStack> {
    X509::from_der(buf.as_ref())
        .map(|crt| vec![crt])
        .or_else(|_| X509::stack_from_pem(buf.as_ref()))
}

/// Read a host-key document from a file.
///
/// # Errors
///
/// This function will return an error if:
/// - The file cannot be read
/// - The content is not valid PEM or DER format
/// - The file contains no certificates or more than 2 certificates
/// - The public key cannot be extracted from the certificate(s)
pub fn read_hkd<P: AsRef<Path>>(path: P) -> Result<HostKey> {
    let path = path.as_ref();
    let hk = read_file(path, "host-key document")?;
    let certs = read_certs(&hk).map_err(|source| Error::HkdNotPemOrDer {
        hkd: path.display().to_string(),
        source,
    })?;
    if certs.is_empty() {
        return Err(Error::NoHkdInFile(path.display().to_string()));
    }
    let c1 = certs.first().unwrap();
    match certs.len() {
        1 => {
            info!("Using version 1 of the host-key document format");
            Ok(HostKey::V1(c1.public_key()?))
        }
        2 => {
            info!("Using version 2 of the host-key document format");
            let c2 = &certs[1];
            Ok(HostKey::V2(HybridPKey::new(
                c1.public_key()?,
                c2.public_key()?,
            )?))
        }
        _ => {
            error!(
                "Invalid host-key document '{}': it contains more than two certificates, which is not supported by any host-key document format.",
                    path.display()
            );
            Err(Error::WrongNumberOfKeys(path.display().to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::*;

    #[test]
    fn read_crls() {
        let crl = get_cert_asset("ibm.crl");
        let crl_der = get_cert_asset("der.crl");
        let fail = get_cert_asset("ibm.crt");
        assert_eq!(super::read_crls(crl).unwrap().len(), 1);
        assert_eq!(super::read_crls(crl_der).unwrap().len(), 1);
        assert_eq!(super::read_crls(fail).unwrap().len(), 0);
    }

    #[test]
    fn read_certs() {
        let crt = get_cert_asset("ibm.crt");
        let crt_der = get_cert_asset("der.crt");
        let fail = get_cert_asset("ibm.crl");
        assert_eq!(super::read_certs(crt).unwrap().len(), 1);
        assert_eq!(super::read_certs(crt_der).unwrap().len(), 1);
        assert_eq!(super::read_certs(fail).unwrap().len(), 0);
    }
}
