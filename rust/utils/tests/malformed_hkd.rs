// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.

//! Integration tests for malformed host key document handling

use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

use pv::request::NoVerifyHkd;
use utils::{AutoOrExplicit, HkdLoader, HkdVersion, TemporaryDirectory};

/// Path to test certificate assets
fn cert_asset_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("pv/tests/assets/cert")
        .join(name)
}

#[test]
fn test_empty_hkd_file() {
    let temp_dir = TemporaryDirectory::new().unwrap();
    let file_path = temp_dir.path().join("empty.hkd");
    File::create(&file_path).unwrap();

    let result = HkdLoader::load_and_verify(&file_path, &NoVerifyHkd, AutoOrExplicit::Auto);
    assert!(result.is_err(), "Empty HKD file should be rejected");

    let err = result.unwrap_err();
    assert!(
        matches!(err, pv::Error::NoHkdInFile(_)),
        "Expected NoHkdInFile error, got: {:?}",
        err
    );
}

#[test]
fn test_invalid_pem_format() {
    // Create a file with invalid PEM content
    let temp_dir = TemporaryDirectory::new().unwrap();
    let file_path = temp_dir.path().join("invalid.hkd");
    let mut temp_file = File::create(&file_path).unwrap();
    writeln!(temp_file, "-----BEGIN CERTIFICATE-----").unwrap();
    writeln!(temp_file, "INVALID_BASE64_CONTENT!!!").unwrap();
    writeln!(temp_file, "-----END CERTIFICATE-----").unwrap();
    temp_file.flush().unwrap();

    // Test that invalid PEM is properly rejected with HkdNotPemOrDer error
    let result = HkdLoader::load_and_verify(&file_path, &NoVerifyHkd, AutoOrExplicit::Auto);
    assert!(result.is_err(), "Invalid PEM format should be rejected");

    let err = result.unwrap_err();
    assert!(
        matches!(err, pv::Error::HkdNotPemOrDer { .. }),
        "Expected HkdNotPemOrDer error, got: {:?}",
        err
    );
}

#[test]
fn test_wrong_number_of_certificates_v1() {
    // Create a file with three valid certificates (invalid count for v1, expects 1)
    let temp_dir = TemporaryDirectory::new().unwrap();
    let file_path = temp_dir.path().join("wrong_count_v1.hkd");
    let mut temp_file = File::create(&file_path).unwrap();

    let cert1 = fs::read_to_string(cert_asset_path("host.crt")).unwrap();
    let cert2 = fs::read_to_string(cert_asset_path("ibm.crt")).unwrap();
    let cert3 = fs::read_to_string(cert_asset_path("root_ca.crt")).unwrap();

    write!(temp_file, "{}{}{}", cert1, cert2, cert3).unwrap();
    temp_file.flush().unwrap();

    let result = HkdLoader::load_and_verify(
        &file_path,
        &NoVerifyHkd,
        AutoOrExplicit::Explicit(HkdVersion::Classical),
    );
    assert!(
        result.is_err(),
        "Wrong number of certificates for v1 should be rejected"
    );

    let err = result.unwrap_err();
    assert!(
        matches!(err, pv::Error::WrongNumberOfKeys(_)),
        "Expected WrongNumberOfKeys error, got: {:?}",
        err
    );
}

#[test]
fn test_wrong_number_of_certificates_v2() {
    // Use existing single certificate file directly (invalid count for v2, expects 2)
    let file_path = cert_asset_path("host.crt");

    // Test that wrong number of certificates is properly rejected with WrongNumberOfKeys error
    let result = HkdLoader::load_and_verify(
        &file_path,
        &NoVerifyHkd,
        AutoOrExplicit::Explicit(HkdVersion::Hybrid),
    );
    assert!(
        result.is_err(),
        "Wrong number of certificates for v2 should be rejected"
    );

    let err = result.unwrap_err();
    assert!(
        matches!(err, pv::Error::WrongNumberOfKeys(_)),
        "Expected WrongNumberOfKeys error, got: {:?}",
        err
    );
}

#[test]
fn test_corrupted_certificate() {
    // Create a file with corrupted certificate data
    let temp_dir = TemporaryDirectory::new().unwrap();
    let file_path = temp_dir.path().join("corrupted.hkd");
    let mut temp_file = File::create(&file_path).unwrap();
    writeln!(temp_file, "-----BEGIN CERTIFICATE-----").unwrap();
    writeln!(
        temp_file,
        "MIICdTCCAd6gAwIBAgIBADANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJVUzEL"
    )
    .unwrap();
    writeln!(temp_file, "CORRUPTED_DATA_HERE").unwrap();
    writeln!(temp_file, "-----END CERTIFICATE-----").unwrap();
    temp_file.flush().unwrap();

    let result = HkdLoader::load_and_verify(&file_path, &NoVerifyHkd, AutoOrExplicit::Auto);
    assert!(result.is_err(), "Corrupted certificate should be rejected");

    let err = result.unwrap_err();
    assert!(
        matches!(err, pv::Error::HkdNotPemOrDer { .. }),
        "Expected HkdNotPemOrDer error, got: {:?}",
        err
    );
}

#[test]
fn test_wrong_key_type_v1() {
    // Use RSA certificate instead of EC-p521 for v1 (should fail)
    let file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("pv/tests/assets/keys/rsa2048.crt");

    let result = HkdLoader::load_and_verify(
        &file_path,
        &NoVerifyHkd,
        AutoOrExplicit::Explicit(HkdVersion::Classical),
    );
    assert!(
        result.is_err(),
        "RSA key should be rejected for v1 (expects EC-p521)"
    );

    let err = result.unwrap_err();
    if let pv::Error::InvalidHkd(msg) = err {
        assert_eq!(
            msg, "First key must be a EC-p521 key",
            "Error message should indicate EC-p521 requirement"
        );
    } else {
        panic!(
            "Expected InvalidHkd error for wrong key type, got: {:?}",
            err
        );
    }
}

#[test]
fn test_wrong_key_type_v2() {
    // Create a file with two RSA certificates instead of EC-p521 + ML-KEM for v2
    let temp_dir = TemporaryDirectory::new().unwrap();
    let file_path = temp_dir.path().join("wrong_key_v2.hkd");
    let mut temp_file = File::create(&file_path).unwrap();

    // Read two RSA certificates and concatenate them
    let rsa_cert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("pv/tests/assets/keys/rsa2048.crt");
    let rsa_cert = fs::read_to_string(&rsa_cert_path).unwrap();

    write!(temp_file, "{}{}", rsa_cert, rsa_cert).unwrap();
    temp_file.flush().unwrap();

    // Test that wrong key types are properly rejected with InvalidHkd error
    let result = HkdLoader::load_and_verify(
        &file_path,
        &NoVerifyHkd,
        AutoOrExplicit::Explicit(HkdVersion::Hybrid),
    );
    assert!(
        result.is_err(),
        "RSA keys should be rejected for v2 (expects EC-p521 + ML-KEM)"
    );

    let err = result.unwrap_err();
    if let pv::Error::InvalidHkd(msg) = err {
        assert_eq!(
            msg, "First key must be a EC-p521 key",
            "Error message should indicate EC-p521 requirement"
        );
    } else {
        panic!(
            "Expected InvalidHkd error for wrong key types, got: {:?}",
            err
        );
    }
}

#[test]
fn test_wrong_second_key_type_v2() {
    // Create a file with EC-p521 + EC (wrong) instead of EC-p521 + ML-KEM for v2
    let temp_dir = TemporaryDirectory::new().unwrap();
    let file_path = temp_dir.path().join("wrong_second_key_v2.hkd");
    let mut temp_file = File::create(&file_path).unwrap();

    let ec_p521_cert = fs::read_to_string(cert_asset_path("host.crt")).unwrap();
    let ec_cert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("pv/tests/assets/keys/host.ec.crt");
    let ec_cert = fs::read_to_string(&ec_cert_path).unwrap();

    write!(temp_file, "{}{}", ec_p521_cert, ec_cert).unwrap();
    temp_file.flush().unwrap();

    let result = HkdLoader::load_and_verify(
        &file_path,
        &NoVerifyHkd,
        AutoOrExplicit::Explicit(HkdVersion::Hybrid),
    );
    assert!(
        result.is_err(),
        "EC key should be rejected as second key for v2 (expects ML-KEM-1024)"
    );

    let err = result.unwrap_err();
    if let pv::Error::InvalidHkd(msg) = err {
        assert_eq!(
            msg, "Second key must be a ML-KEM 1024 key",
            "Error message should indicate ML-KEM-1024 requirement"
        );
    } else {
        panic!(
            "Expected InvalidHkd error for wrong second key type, got: {:?}",
            err
        );
    }
}
