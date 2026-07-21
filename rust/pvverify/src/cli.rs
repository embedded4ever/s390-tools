// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2025
use std::sync::OnceLock;

use clap::{ArgAction, Parser, ValueEnum};
use utils::{
    AutoOrExplicit, AutoOrExplicitParser, CertificateOptions, HkdVersion, ValueEnumDisplay,
    ValueEnumFromStr,
};

static VERSION: OnceLock<String> = OnceLock::new();

/// Secure Execution HostKey version for CLI
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, ValueEnumDisplay, ValueEnumFromStr)]
pub enum HostKeyVersion {
    #[value(name = "1")]
    /// Version 1 - uses traditional cryptographic keys
    V1,
    #[value(name = "2")]
    /// Version 2 - uses hybrid (post-quantum) cryptographic keys
    V2,
}
pub type HostKeyVersionSelection = AutoOrExplicit<HostKeyVersion>;
pub type HostKeyVersionSelectionParser = AutoOrExplicitParser<HostKeyVersion>;

impl From<HostKeyVersion> for HkdVersion {
    fn from(val: HostKeyVersion) -> Self {
        match val {
            HostKeyVersion::V1 => Self::Classical,
            HostKeyVersion::V2 => Self::Hybrid,
        }
    }
}

#[derive(Parser, Debug)]
#[command(long_version=ver(), disable_version_flag(true))]
/// Tool to verify host-keys
///
/// Tool to verify host-keys. Use this tool to verify the chain of trust for IBM Secure
// Allow manual_non_exhaustive to suppress Clippy false positive as the version
// field is used by Clap to generate the --version flag.
#[allow(clippy::manual_non_exhaustive)]
pub struct CliOptions {
    #[command(flatten)]
    pub certificate_args: CertificateOptions,

    #[arg(long, action=ArgAction::Version)]
    /// Print version information and exit.
    version: (),

    /// Specify the Host-key version to use.
    #[arg(long = "hkd-version", value_name = "VERSION", default_value_t = HostKeyVersionSelection::Auto, value_parser = HostKeyVersionSelectionParser::default())]
    pub hkd_version: HostKeyVersionSelection,
}

fn ver() -> &'static str {
    VERSION.get_or_init(|| utils::tools_version_fmt!(2025))
}
