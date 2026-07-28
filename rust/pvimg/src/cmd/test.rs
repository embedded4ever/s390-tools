// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::path::Path;

use anyhow::Result;
use log::{info, warn};
use pv::misc::open_file;
use pv::request::NoVerifyHkd;
use pv::{FileAccessErrorType, PvCoreError};
use pvimg::error::{Error, OwnExitCode};
use pvimg::uvdata::{KeyExchangeTrait, SeHdr, UvKeyHashesV1};
use utils::hkd::{HkdLoader, HkdVersionSelection};
use utils::HexSlice;

use crate::cli::TestArgs;
use crate::log_println;

/// Returns `Ok(true)` if at least one of the hashes is included.
fn hdr_test_target_hashes(hdr: &SeHdr, key_hashes: &Path) -> Result<bool> {
    let file = open_file(key_hashes).map_err(|err| match err {
        PvCoreError::FileAccess {
            ref ty,
            ref path,
            ref source,
        } if matches!(ty, FileAccessErrorType::Open)
            && source.kind() == std::io::ErrorKind::NotFound
            && path == Path::new(UvKeyHashesV1::SYS_UV_KEYS_ALL) =>
        {
            Error::UnavailableQueryUvKeyHashesSupport { source: err }
        }
        err => Error::PvCore(err),
    })?;
    let hashes = UvKeyHashesV1::read_from_io(file)?;
    let matches = hashes.matching_hashes(hdr);
    if matches.is_empty() {
        warn!(" ✘ None of the key hashes is included");
        Ok(false)
    } else {
        for m in matches {
            match m.idx.kind() {
                Some(kind) => {
                    log_println!(" ✓ {kind} {:#} is included", HexSlice::from(&m.hash))
                }
                None => log_println!(
                    " ✓ Key hash {:#} is included (zero-based index {})",
                    HexSlice::from(&m.hash),
                    m.idx.index()
                ),
            }
        }
        Ok(true)
    }
}

/// Returns `Ok(true)` if at least one of the given public key of the host key
/// documents was used for the image creation or if no host key document was
/// specified.
fn hdr_test_hkd<P>(hdr: &SeHdr, host_key_documents: &[P]) -> Result<bool>
where
    P: AsRef<Path>,
{
    if host_key_documents.is_empty() {
        return Ok(true);
    }

    let mut result = false;
    for path in host_key_documents {
        let hkd = HkdLoader::load_and_verify(
            path,
            &NoVerifyHkd,
            HkdVersionSelection::Explicit(hdr.common.version.into()),
        )?;
        if hdr.contains(hkd)? {
            result = true;
            log_println!(
                " ✓ Host key document '{}' is included",
                path.as_ref().display()
            );
        } else {
            log_println!(
                " ✘ Host key document '{}' is not included",
                path.as_ref().display()
            );
        }
    }
    Ok(result)
}

pub fn test(opt: &TestArgs) -> Result<OwnExitCode> {
    info!("Testing a Secure Execution image");

    let mut input = open_file(&opt.input.path)?;
    SeHdr::seek_sehdr(&mut input, None)?;
    let hdr = SeHdr::try_from_io(input)?;

    let mut success = hdr_test_hkd(&hdr, &opt.host_key_documents)?;
    if let Some(path) = &opt.key_hashes {
        success = hdr_test_target_hashes(&hdr, path)? && success;
    }

    Ok(if success {
        OwnExitCode::Success
    } else {
        OwnExitCode::GenericError
    })
}
