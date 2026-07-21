// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::env;
use std::ffi::OsStr;
use std::fmt::Display;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::str::FromStr;
use std::string::ToString;

use clap::builder::{PossibleValue, TypedValueParser};
use clap::{Arg, ArgGroup, Args, Command, CommandFactory, Parser, ValueEnum, ValueHint};
use log::warn;
use utils::{
    AutoOrExplicit, CertificateOptions, DeprecatedVerbosityOptions, HkdVersion, ValueEnumDisplay,
    ValueEnumFromStr,
};

/// SE header control flags for CLI
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, ValueEnum, ValueEnumDisplay)]
#[value(rename_all = "kebab-case")]
pub enum SeHdrFlagName {
    /// Confidential guest dump support
    ConfidentialDump,
    /// DEA/TDEA PCKMO key encryption support
    PckmoDeaTdea,
    /// AES PCKMO key encryption support
    PckmoAes,
    /// ECC PCKMO key encryption support
    PckmoEcc,
    /// HMAC PCKMO key encryption support
    PckmoHmac,
    /// Backup target keys support
    BackupTargetKeys,
    /// CCK-derived extension secret enforcement for add-secret requests
    CckExtensionSecretEnforcement,
    /// CCK update support
    CckUpdate,
    /// Image components without encryption
    NoComponentEncryption,
}

/// Secure Execution header version for CLI
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, ValueEnumDisplay, ValueEnumFromStr)]
pub enum HdrVersion {
    #[value(name = "1")]
    /// Version 1 - uses traditional cryptographic keys
    V1,
    #[value(name = "2")]
    /// Version 2 - uses hybrid (post-quantum) cryptographic keys
    V2,
}

pub type HdrVersionSelection = AutoOrExplicit<HdrVersion>;

impl From<HdrVersion> for HkdVersion {
    fn from(val: HdrVersion) -> Self {
        match val {
            HdrVersion::V1 => Self::Classical,
            HdrVersion::V2 => Self::Hybrid,
        }
    }
}

/// Create and inspect IBM Secure Execution images.
///
/// Use pvimg to create an IBM Secure Execution image, which can be loaded using
/// zipl or QEMU. pvimg can also be used to inspect existing Secure Execution
/// images.
#[derive(Parser, Debug)]
#[command()]
pub struct CliOptions {
    #[clap(flatten)]
    pub verbose: DeprecatedVerbosityOptions,

    /// Print version information and exit.
    // Implemented for the help message only. Actual parsing happens in the
    // version command.
    #[arg(long)]
    pub version: bool,

    #[command(subcommand)]
    pub cmd: SubCommands,
}

impl From<GenprotimgCliOptions> for CliOptions {
    fn from(value: GenprotimgCliOptions) -> Self {
        Self {
            verbose: value.verbose,
            version: false,
            cmd: SubCommands::Create(value.args),
        }
    }
}

impl CliOptions {
    pub fn new_version_cmd_opts() -> Self {
        Self {
            verbose: DeprecatedVerbosityOptions::default(),
            version: true,
            cmd: SubCommands::Version,
        }
    }
}

/// Defines a requirement rule for CLI validation.
///
/// A requirement specifies that certain flags require a specific option to be present.
/// For example, the `ConfidentialDump` flag requires the `--cck` option.
struct Requirement {
    /// The flags that trigger this requirement
    flags: &'static [SeHdrFlagName],
    /// The option name that must be present (e.g., "cck")
    option: &'static str,
    /// Whether the required option is present
    present: bool,
}

/// Defines a set of flags that cannot be used together.
///
/// When multiple flags from this set are present in the command line,
/// a validation error is raised with a dynamically generated message
/// listing the conflicting flags.
struct MutuallyExclusiveFlags {
    flags: &'static [SeHdrFlagName],
}

/// Validates the given command line options.
///
/// # Errors
///
/// This function will return an error if an argument is missing.
pub fn validate_cli(opts: &CliOptions) -> Result<(), clap::error::Error> {
    match &opts.cmd {
        SubCommands::Create(create_opts) => {
            if let Some(dir) = create_opts
                .experimental_args
                .x_bootloader_directory
                .as_ref()
            {
                warn!("Use bootloader directory: {}", dir.display());
            }

            // Check that a user provided CCK is available
            let rules = [Requirement {
                flags: &[
                    SeHdrFlagName::ConfidentialDump,
                    SeHdrFlagName::CckExtensionSecretEnforcement,
                ],
                option: LONG_FLAG_CCK,
                present: create_opts.keys.cck.is_some(),
            }];
            for r in rules {
                let offenders: Vec<_> = r
                    .flags
                    .iter()
                    .filter(|f| create_opts.flags.contains(f))
                    .collect();

                if !offenders.is_empty() && !r.present {
                    return Err(clap::Error::raw(
                        clap::error::ErrorKind::MissingRequiredArgument,
                        format!(
                            "flag(s) {} require(s) --{}",
                            offenders
                                .iter()
                                .map(|f| format!("{:?}", f))
                                .collect::<Vec<_>>()
                                .join(", "),
                            r.option
                        ),
                    ));
                }
            }

            // Check for conflicts between --flags and --disable-flags
            if !create_opts.flags.is_empty() && !create_opts.disable_flags.is_empty() {
                use std::collections::HashSet;
                let flags_set: HashSet<_> = create_opts.flags.iter().collect();
                let disable_flags_set: HashSet<_> = create_opts.disable_flags.iter().collect();

                let conflicts: Vec<_> = flags_set
                    .intersection(&disable_flags_set)
                    .copied()
                    .collect();

                if !conflicts.is_empty() {
                    return Err(clap::Error::raw(
                        clap::error::ErrorKind::ArgumentConflict,
                        // Print the flag name using the kebab-case notation (using to_possible_value)
                        format!(
                            "Conflicting flags detected: the following flags are specified in both --flags and --disable-flags: {}",
                            conflicts.iter().map(|x| format!("{x}")).collect::<Vec<_>>().join(", ")
                        ),
                    ));
                }
            }

            // Check for mutually exclusive flags within --flags
            let exclusion_rules = [MutuallyExclusiveFlags {
                flags: &[
                    SeHdrFlagName::CckExtensionSecretEnforcement,
                    SeHdrFlagName::CckUpdate,
                ],
            }];

            for rule in exclusion_rules {
                let conflicting_flags: Vec<_> = rule
                    .flags
                    .iter()
                    .filter(|f| create_opts.flags.contains(f))
                    .collect();

                if conflicting_flags.len() > 1 {
                    return Err(clap::Error::raw(
                        clap::error::ErrorKind::ArgumentConflict,
                        format!(
                            "The following flags cannot be used together: {}",
                            conflicting_flags
                                .iter()
                                .map(|f| format!("'{}'", f))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    ));
                }
            }

            Ok(())
        }
        _ => Ok(()),
    }
}

/// CLI Argument collection for handling input components.
#[derive(Args, Debug)]
#[cfg_attr(test, derive(Default))]
pub struct ComponentPaths {
    /// Use the content of FILE as a raw binary Linux kernel.
    ///
    /// The Linux kernel must be a raw binary s390x Linux kernel. The ELF format
    /// is not supported.
    #[arg(short='i', long = "kernel", value_name = "FILE", value_hint = ValueHint::FilePath, visible_alias = "image")]
    pub kernel: PathBuf,

    /// Use the content of FILE as the Linux initial RAM disk.
    #[arg(short, long, value_name = "FILE", value_hint = ValueHint::FilePath)]
    pub ramdisk: Option<PathBuf>,

    /// Use the content of FILE as the Linux kernel command line.
    ///
    /// The Linux kernel command line must be shorter than the maximum kernel
    /// command line size supported by the given Linux kernel.
    #[arg(short, long, value_name = "FILE", value_hint = ValueHint::FilePath)]
    pub parmfile: Option<PathBuf>,
}

const LONG_FLAG_CCK: &str = "cck";

/// CLI Argument collection for handling user-provided keys.
#[derive(Args, Debug)]
#[cfg_attr(test, derive(Default))]
pub struct UserKeys {
    /// Use the content of FILE as the customer-communication key (CCK).
    ///
    /// The file must contain exactly 32 bytes of data. In previous versions,
    /// this option was called '--comm-key'.
    #[arg(
        long = LONG_FLAG_CCK,
        value_name = "FILE",
        group = "cck-available",
        visible_alias = "comm-key"
    )]
    pub cck: Option<PathBuf>,

    /// Use the content of FILE as the Secure Execution header protection key.
    ///
    /// The file must contain exactly 32 bytes of data. If the option is not
    /// specified, the Secure Execution header protection key is a randomly
    /// generated key.
    #[arg(long, value_name = "FILE", alias = "x-header-key")]
    pub hdr_key: Option<PathBuf>,

    /// Use the content of FILE as the image encryption key.
    ///
    /// The file must contain exactly 64 bytes of data.
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with = "disable_image_encryption",
        alias = "x-comp-key"
    )]
    pub image_key: Option<PathBuf>,
}

#[derive(Args, Debug)]
#[cfg_attr(test, derive(Default))]
#[command(
    group(ArgGroup::new("header-flags").multiple(true).conflicts_with_all(["x_pcf", "x_scf"])),
    group(ArgGroup::new("cck-available").multiple(true)))]
pub struct CreateBootImageLegacyFlags {
    /// Enable Secure Execution guest dump support. This option requires the
    /// '--cck' or '--enable-cck-update' option.
    #[arg(long, action = clap::ArgAction::SetTrue, requires = "cck-available", group="header-flags")]
    pub enable_dump: Option<bool>,

    /// Disable Secure Execution guest dump support (default).
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with="enable_dump", group="header-flags")]
    pub disable_dump: Option<bool>,

    /// Add-secret requests must provide an extension secret that matches the
    /// CCK-derived extension secret. This option requires the '--cck'
    /// option.
    // Note: We intentionally require 'cck' (not 'cck-available') because
    // enable-cck-extension-secret cannot be used together with
    // --enable-cck-update.
    #[arg(long, action = clap::ArgAction::SetTrue, requires="cck", group="header-flags")]
    pub enable_cck_extension_secret: Option<bool>,

    /// Add-secret requests don't have to provide the CCK-derived extension
    /// secret (default).
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with="enable_cck_extension_secret", group="header-flags")]
    pub disable_cck_extension_secret: Option<bool>,

    /// Enable CCK update support. Requires z17 or up. This option cannot be
    /// used in conjunction with the '--enable-cck-extension-secret' option.
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with="enable_cck_extension_secret", group="cck-available", group="header-flags")]
    pub enable_cck_update: Option<bool>,

    /// Disable CCK update support (default).
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with="enable_cck_update", group="header-flags")]
    pub disable_cck_update: Option<bool>,

    /// Enable the support for the DEA, TDEA, AES, and ECC PCKMO key encryption
    /// functions (default).
    #[arg(long, action = clap::ArgAction::SetTrue, group="header-flags")]
    pub enable_pckmo: Option<bool>,

    /// Disable the support for the DEA, TDEA, AES, and ECC PCKMO key encryption
    /// functions.
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with="enable_pckmo", group="header-flags")]
    pub disable_pckmo: Option<bool>,

    /// Enable the support for the HMAC PCKMO key encryption function (default for header version
    /// 2).
    #[arg(long, action = clap::ArgAction::SetTrue, group="header-flags")]
    pub enable_pckmo_hmac: Option<bool>,

    /// Disable the support for the HMAC PCKMO key encryption function (default for header version
    /// 1).
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with="enable_pckmo_hmac", group="header-flags")]
    pub disable_pckmo_hmac: Option<bool>,

    /// Enable the support for backup target keys.
    #[arg(long, action = clap::ArgAction::SetTrue, group="header-flags")]
    pub enable_backup_keys: Option<bool>,

    /// Disable the support for backup target keys (default).
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with="enable_backup_keys", group="header-flags")]
    pub disable_backup_keys: Option<bool>,

    /// Enable encryption of the image components (default).
    ///
    /// The image components are: the kernel, ramdisk, and kernel command line.
    #[arg(long, action = clap::ArgAction::SetTrue, group="header-flags")]
    pub enable_image_encryption: Option<bool>,

    /// Disable encryption of the image components.
    ///
    /// The image components are: the kernel, ramdisk, and kernel command line.
    /// Use only if the components used do not contain any confidential content
    /// (for example, secrets like non-public cryptographic keys).
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with="enable_image_encryption", group="header-flags")]
    pub disable_image_encryption: Option<bool>,
}

#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum OutputFormatKind {
    /// Human-readable, unstable text format
    Text,
    /// JSON format.
    Json,
}

impl Display for OutputFormatKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text => write!(f, "human-readable"),
            Self::Json => write!(f, "JSON"),
        }
    }
}

impl FromStr for OutputFormatKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            _ => Err(format!("Invalid output format: {s}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormatVariant {
    /// Default
    Default,
    /// Full
    Full,
    /// Minified
    Minify,
    /// Pretty
    Pretty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputFormatSpec {
    pub kind: OutputFormatKind,
    pub variant: OutputFormatVariant,
}

impl OutputFormatSpec {
    pub fn detect() -> Self {
        let kind = if std::io::stdout().is_terminal() {
            OutputFormatKind::Text
        } else {
            OutputFormatKind::Json
        };
        Self {
            kind,
            variant: OutputFormatVariant::Default,
        }
    }
}

#[derive(Clone, Default)]
struct OutputFormatSpecParser;

impl TypedValueParser for OutputFormatSpecParser {
    type Value = OutputFormatSpec;

    fn parse_ref(
        &self,
        cmd: &Command,
        arg: Option<&Arg>,
        value: &OsStr,
    ) -> Result<Self::Value, clap::error::Error> {
        let s = value.to_string_lossy();
        let mut parts = s.splitn(2, ':');
        let arg_name = arg.unwrap().get_id().to_string();
        let kind_s = parts.next().unwrap().to_ascii_lowercase();
        let variant_s = parts.next().map(|x| x.to_ascii_lowercase());
        let kind = kind_s.as_str().parse().map_err(|_| {
            let mut err =
                clap::error::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd);
            err.insert(
                clap::error::ContextKind::InvalidArg,
                clap::error::ContextValue::String(arg_name.clone()),
            );
            err.insert(
                clap::error::ContextKind::InvalidValue,
                clap::error::ContextValue::String(kind_s.to_string()),
            );
            err
        })?;

        let variant = match (kind, variant_s.as_deref()) {
            (_, None) => OutputFormatVariant::Default,
            (_, Some("default")) => OutputFormatVariant::Default,

            (OutputFormatKind::Text, Some("full")) => OutputFormatVariant::Full,
            (OutputFormatKind::Json, Some("pretty")) => OutputFormatVariant::Pretty,
            (OutputFormatKind::Json, Some("minify")) => OutputFormatVariant::Minify,
            (_, Some(other)) => {
                let mut err =
                    clap::error::Error::new(clap::error::ErrorKind::ValueValidation).with_cmd(cmd);
                err.insert(
                    clap::error::ContextKind::InvalidArg,
                    clap::error::ContextValue::String(arg_name.clone()),
                );
                err.insert(
                    clap::error::ContextKind::InvalidValue,
                    clap::error::ContextValue::String(format!("{kind_s}:{other}")),
                );
                Err(err)?
            }
        };

        Ok(OutputFormatSpec { kind, variant })
    }

    // This is used for shell completion suggestions for `--format`
    fn possible_values(&self) -> Option<Box<dyn Iterator<Item = PossibleValue> + '_>> {
        use clap::builder::PossibleValue as PV;

        let vals: Vec<PV> = vec![
            PV::new("text")
                .help("Human-readable, unstable text format (default if a terminal is available)"),
            PV::new("text:full").help("Human-readable, full detail text format"),
            PV::new("json")
                .help("Pretty-printed machine-readable JSON (default if no terminal available)"),
            PV::new("json:pretty").help("Pretty-printed machine-readable JSON"),
            PV::new("json:minify").help("Minified machine-readable JSON"),
        ];
        Some(Box::new(vals.into_iter()))
    }
}

#[derive(Args, Debug)]
pub struct SeImgInputArgs {
    /// Use INPUT as the Secure Execution image.
    #[arg(value_name = "INPUT", value_hint = ValueHint::FilePath,)]
    pub path: PathBuf,
}

#[derive(Args, Debug)]
#[command(group(ArgGroup::new("info-mode").required(true).args(["path", "print_schema"])))]
pub struct InfoArgs {
    #[clap(flatten)]
    pub input: Option<SeImgInputArgs>,

    /// Output format for the Secure Execution image information.
    ///
    /// If not specified, the format is automatically determined based on
    /// whether stdout is connected to a terminal.
    #[arg(long, value_parser=OutputFormatSpecParser::default(), conflicts_with = "print_schema")]
    pub format: Option<OutputFormatSpec>,

    /// Use the key in FILE to verify the Secure Execution header and optionally
    /// use '--show-secrets' to decrypt it.
    ///
    /// The key must be the same key that was specified with '--hdr-key' when the
    /// Secure Execution image was created. The key is used to:
    ///   1. Verify the integrity and authenticity of the header
    ///   2. Optionally decrypt secrets with '--show-secrets'
    ///
    /// Without this option, the information is displayed, but NOT verified, and
    /// a warning is printed. The displayed data should not be trusted without
    /// verification.
    #[arg(long, value_name = "FILE", value_hint = ValueHint::FilePath, alias = "key", verbatim_doc_comment, conflicts_with = "print_schema")]
    pub hdr_key: Option<PathBuf>,

    /// This option reveals sensitive information that is normally encrypted in
    /// the header, such as:
    ///   - Customer communication key (CCK)
    ///   - Image encryption key
    ///   - Other confidential data
    ///
    /// SECURITY WARNING: Only use this option in secure, trusted environments.
    /// The decrypted secrets should never be exposed in untrusted systems.
    ///
    /// This option requires '--hdr-key' to decrypt the header.
    #[arg(
        long,
        requires = "hdr_key",
        verbatim_doc_comment,
        conflicts_with = "print_schema"
    )]
    pub show_secrets: bool,

    /// Print the schema for the 'info' subcommand and exit.
    ///
    /// This outputs the schema that describes the structure of the given output FORMAT
    /// produced by the 'info' subcommand. The schema can be used for:
    ///   - Validating output
    ///   - Building tools that parse the output
    #[arg(value_name = "FORMAT", long, verbatim_doc_comment)]
    pub print_schema: Option<OutputFormatKind>,
}

#[derive(Args, Debug)]
#[command(group(ArgGroup::new("test-args").multiple(true).required(true)))]
pub struct TestArgs {
    #[clap(flatten)]
    pub input: SeImgInputArgs,

    /// Use FILE to check for a host key document.
    ///
    /// Verifies that the image contains the host key hash of one of the
    /// specified host keys. The check fails if none of the host keys match the
    /// hash in the image. This parameter can be specified multiple times.
    /// Mutually exclusive with '--key-hashes'.
    #[arg(
        short = 'k',
        long = "host-key-document",
        value_name = "FILE",
        value_hint = ValueHint::FilePath,
        use_value_delimiter = true,
        value_delimiter = ',',
        group = "test-args",
        )]
    pub host_key_documents: Vec<PathBuf>,

    /// Use FILE to check for the host key hashes provided by the ultravisor. If
    /// no FILE is specified, FILE defaults to '/sys/firmware/uv/keys/all'.
    ///
    /// The default file is only available if the local system supports the
    /// Query Ultravisor Keys UVC. Verifies that the image contains the host key
    /// hash of one of the specified hashes in FILE. The check fails if none of
    /// the host keys match a hash in the response. Mutually exclusive with
    /// '--host-key-document'.
    #[arg(
        long = "key-hashes",
        value_name = "FILE",
        value_hint = ValueHint::FilePath,
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "/sys/firmware/uv/keys/all",
        conflicts_with="host_key_documents",
        group = "test-args",
        )]
    pub key_hashes: Option<PathBuf>,
}

/// Create an IBM Secure Execution image.
///
/// Create a new IBM Secure Execution image. Only create these images in a
/// trusted environment, such as your workstation. The 'genprotimg' command
/// creates randomly generated keys to protect the image. The generated image
/// can then be booted on an IBM Secure Execution system as a KVM guest.
///
/// Note: The 'genprotimg' command is a symbolic link to the 'pvimg create'
///       command.
#[derive(Parser, Debug)]
pub struct GenprotimgCliOptions {
    #[clap(flatten)]
    pub args: Box<CreateBootImageArgs>,

    #[clap(flatten)]
    pub verbose: DeprecatedVerbosityOptions,

    /// Print version information and exit.
    // Implemented for the help message only. Actual parsing happens in the
    // version command.
    #[arg(long, action = clap::ArgAction::SetTrue )]
    pub version: (),

    #[arg(long, action = clap::ArgAction::HelpLong, hide(true))]
    /// Print help (deprecated, use '--help' instead).
    help_all: (),

    #[arg(long, action = clap::ArgAction::HelpLong, hide(true))]
    /// Print help (deprecated, use '--help' instead).
    help_experimental: (),
}

impl GenprotimgCliOptions {
    pub fn command() -> Command {
        let cmd = <Self as CommandFactory>::command();
        // Make sure that the correct binary is shown in the clap error
        // messages.
        cmd.bin_name("genprotimg")
    }

    pub fn own_parse() -> CliOptions {
        let args = env::args_os();
        let args_len = args.len();
        let version_count = args.filter(|value| value == "--version").count();
        if version_count > 1 || version_count == 1 && (args_len != version_count + 1) {
            Self::command()
                .error(
                    clap::error::ErrorKind::UnknownArgument,
                    "unexpected argument",
                )
                .exit()
        }

        if version_count == 1 {
            CliOptions::new_version_cmd_opts()
        } else {
            let genprotimg_opts = Self::parse();
            genprotimg_opts.into()
        }
    }
}

#[derive(Parser, Debug)]
pub struct CreateBootImageArgs {
    #[clap(flatten)]
    pub component_paths: ComponentPaths,

    /// Write the generated Secure Execution boot image to FILE.
    #[arg(short, long, value_name = "FILE", value_hint = ValueHint::FilePath,)]
    pub output: PathBuf,

    #[clap(flatten)]
    pub certificate_args: CertificateOptions,

    /// Disable all input component checks.
    ///
    /// For example, for the Linux kernel, it tests if the given kernel looks
    /// like a raw binary s390x kernel.
    #[arg(long)]
    pub no_component_check: bool,

    /// Overwrite an existing Secure Execution boot image.
    #[arg(long)]
    pub overwrite: bool,

    /// Specify the Secure Execution header version to use.
    #[arg(long = "hdr-version", value_name = "VERSION", default_value_t = HdrVersion::V1)]
    pub hdr_version: HdrVersion,

    #[clap(flatten)]
    pub keys: UserKeys,

    #[clap(flatten)]
    // TODO Declare as deprecated
    pub legacy_flags: CreateBootImageLegacyFlags,

    /// Set control flags using comma-separated flag names.
    ///
    /// Specify flags to enable using their names.
    #[arg(
        long,
        value_name = "FLAGS",
        value_delimiter = ',',
        conflicts_with_all = ["header-flags", "x_pcf", "x_scf"]
    )]
    pub flags: Vec<SeHdrFlagName>,

    /// Set control flags using comma-separated flag names.
    ///
    /// Specify flags to disable using their names.
    #[arg(
        long,
        value_name = "FLAGS",
        value_delimiter = ',',
        conflicts_with_all = ["header-flags", "x_pcf", "x_scf"]
    )]
    pub disable_flags: Vec<SeHdrFlagName>,

    #[clap(flatten)]
    pub experimental_args: CreateBootImageExperimentalArgs,
}

#[cfg(test)]
impl Default for CreateBootImageArgs {
    fn default() -> Self {
        Self {
            component_paths: ComponentPaths::default(),
            output: PathBuf::new(),
            certificate_args: CertificateOptions::default(),
            no_component_check: false,
            overwrite: false,
            hdr_version: HdrVersion::V1,
            keys: UserKeys::default(),
            legacy_flags: CreateBootImageLegacyFlags::default(),
            flags: Vec::new(),
            disable_flags: Vec::new(),
            experimental_args: CreateBootImageExperimentalArgs::default(),
        }
    }
}

/// Experimental options
#[derive(Args, Debug)]
#[cfg_attr(test, derive(Default))]
pub struct CreateBootImageExperimentalArgs {
    /// Manually set the directory used to load the Secure Execution bootloaders
    /// (stage3a and stage3b) (experimental option).
    // Hidden in user documentation.
    #[arg(long, value_name = "DIR", hide(true))]
    pub x_bootloader_directory: Option<PathBuf>,

    /// Manually set the PSW address used for the Secure Execution header (experimental option).
    // Hidden in user documentation.
    #[arg(long, value_name = "ADDRESS", hide(true))]
    pub x_psw: Option<String>,

    /// Manually set the plaintext control flags (experimental option).
    // No validity checks made. Hidden in user documentation.
    #[arg(long, value_name = "PCF", hide(true))]
    pub x_pcf: Option<String>,

    /// Manually set the secret control flags (experimental option).
    // No validity checks made. Hidden in user documentation.
    #[arg(long, value_name = "SCF", hide(true))]
    pub x_scf: Option<String>,
}

#[derive(Debug, clap::Subcommand)]
pub enum SubCommands {
    /// Create an IBM Secure Execution image.
    ///
    /// Create a new IBM Secure Execution image. Only create these images in a
    /// trusted environment, such as your workstation. The 'pvimg create'
    /// command creates randomly generated keys to protect the image. The
    /// generated image can then be booted on an IBM Secure Execution system as
    /// a KVM guest.
    Create(Box<CreateBootImageArgs>),

    /// Print information about the IBM Secure Execution image.
    ///
    /// The 'info' subcommand extracts and displays information about an
    /// existing IBM Secure Execution image, including information from the
    /// Secure Execution header. By default, the header is displayed without
    /// verifying its integrity and authenticity. Use '--hdr-key' to
    /// authenticate and verify the header integrity.
    ///
    /// Output can be formatted as human-readable text or JSON. Use '--format'
    /// to control the output format and level of detail.
    ///
    /// SECURITY NOTE: Without '--hdr-key', the displayed information is NOT
    /// verified and should not be trusted.
    Info(InfoArgs),

    /// Test different aspects of an existing IBM Secure Execution image.
    Test(Box<TestArgs>),

    /// Print version information and exit.
    #[command(aliases(["--version"]), hide(true))]
    Version,
}

#[allow(clippy::shadow_unrelated)]
#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use super::*;

    #[derive(Hash, Eq, PartialEq, Debug, Clone)]
    struct CliOption {
        name: String,
        args: Vec<String>,
    }

    impl CliOption {
        fn new<S: AsRef<str>, T: AsRef<str>, P: AsRef<[S]>>(name: T, args: P) -> Self {
            let name = name.as_ref().to_owned();
            let args = args
                .as_ref()
                .iter()
                .map(|v| v.as_ref().to_owned())
                .collect();
            Self { name, args }
        }
    }

    impl From<CliOption> for Vec<String> {
        fn from(val: CliOption) -> Self {
            let CliOption { args, .. } = val;
            args
        }
    }

    fn flat_map_collect(map: BTreeMap<String, CliOption>) -> Vec<String> {
        map.into_values().flat_map(|v| v.args).collect()
    }

    fn insert(
        mut map: BTreeMap<String, CliOption>,
        values: Vec<CliOption>,
    ) -> BTreeMap<String, CliOption> {
        for value in values {
            map.insert(value.name.to_owned(), value);
        }
        map
    }

    fn remove<S: AsRef<str>>(
        mut map: BTreeMap<String, CliOption>,
        key: S,
    ) -> BTreeMap<String, CliOption> {
        map.remove(key.as_ref());
        map
    }

    // Helper to test valid args - generic over parse and convert functions
    fn test_valid_args<F>(args_list: Vec<Vec<&str>>, parse_and_convert: F, name: &str)
    where
        F: Fn(&[&str]) -> Result<CliOptions, clap::Error>,
    {
        for arg in args_list {
            let res = parse_and_convert(&arg);
            #[allow(clippy::use_debug, clippy::print_stdout)]
            if let Err(e) = &res {
                println!("{name} arg: {arg:?}");
                println!("{e}");
            }
            assert!(res.is_ok(), "{name} failed for: {arg:?}");
        }
    }

    // Helper to test invalid args - expects parse or validation to fail
    fn test_invalid_args<F>(
        test_cases: &[(&[Vec<String>], clap::error::ErrorKind, &str)],
        cmd_prefix: &[&str],
        parse_and_convert: F,
        name: &str,
    ) where
        F: Fn(&[&str]) -> Result<CliOptions, clap::Error>,
    {
        for (test_group, expected_kind, kind_name) in test_cases {
            for args in *test_group {
                let full_args = [
                    cmd_prefix.to_vec(),
                    Vec::from_iter(args.iter().map(String::as_str)),
                ]
                .concat();

                // Try parse and convert
                let parse_result = parse_and_convert(&full_args);

                let err = match parse_result {
                    Ok(cli_opts) => {
                        // Parse succeeded, validation must fail
                        validate_cli(&cli_opts).expect_err(&format!(
                            "{name}: Expected error ({kind_name}) but both parse and validation succeeded for: {full_args:?}"
                        ))
                    }
                    Err(e) => e, // Parse failed as expected
                };

                assert_eq!(
                    err.kind(),
                    *expected_kind,
                    "{name}: Expected {kind_name} but got {:?} for args: {full_args:?}\nError: {err}",
                    err.kind()
                );
            }
        }
    }

    #[test]
    #[rustfmt::skip]
    fn genprotimg_and_pvimg_create_args() {
        // Minimal valid create arguments using no-verify
        let mut mvcanv = BTreeMap::new();
        mvcanv = insert(mvcanv, vec![CliOption::new("image", ["--image", "/dev/null"])]);
        mvcanv = insert(mvcanv, vec![CliOption::new("hkd", ["--host-key-document", "/dev/null"])]);
        mvcanv = insert(mvcanv, vec![CliOption::new("output", ["--output", "/dev/null"])]);
        mvcanv = insert(mvcanv, vec![CliOption::new("no-verify", ["--no-verify"])]);

        // Minimal valid create arguments using --cert
        let mut mvca = mvcanv.clone();
        mvca.remove("no-verify");
        mvca = insert(mvca, vec![CliOption::new("cert", ["--cert", "/dev/null"])]);

        let valid_create_args = [
            flat_map_collect(mvcanv.clone()),
            flat_map_collect(insert(remove(mvcanv.clone(), "image"), vec![CliOption::new("kernel", ["--kernel", "/dev/kernel"])])),
            flat_map_collect(insert(mvcanv.clone(), vec![CliOption::new("root-ca", ["--root-ca", "/dev/null"])])),
            flat_map_collect(mvca.clone()),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("quiet", ["-q"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("verbose", ["-vvv"])])),
            // Verify the old verbosity is still working.
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("verbose", ["-VVV"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("offline", ["--offline"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("ramdisk", ["--ramdisk", "/dev/null"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("parmfile", ["--parmfile", "/dev/null"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-dump", ["--enable-dump"]),
                                                   CliOption::new("comm-key", ["--comm-key", "/dev/null"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-dump", ["--enable-dump"]),
                                                   CliOption::new("comm-key", ["--cck", "/dev/null"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-dump", ["--enable-dump"]),
                                                   CliOption::new("comm-key", ["--comm-key", "/dev/null"]),
                                                   CliOption::new("enable-cck-update", ["--enable-cck-update"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("x-pcf", ["--x-pcf", "0x0"]),
                                                   CliOption::new("x-scf", ["--x-scf", "0x0"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("x-psw", ["--x-psw", "0x0"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("no-component-check", ["--no-component-check"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-pckmo", ["--enable-pckmo"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-pckmo-hmac", ["--enable-pckmo-hmac"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-backup-keys", ["--enable-backup-keys"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("disable-image-encryption", ["--disable-image-encryption"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-image-encryption", ["--enable-image-encryption"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("x-header-key", ["--x-header-key", "/dev/null"]),])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("x-header-key", ["--hdr-key", "/dev/null"]),])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-cck-update", ["--enable-cck-update"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("disable-cck-update", ["--disable-cck-update"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("multiple-cck", ["--disable-cck-update", "--cck", "/dev/null"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("x-comp-key", ["--x-comp-key", "/dev/null"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("image-key", ["--image-key", "/dev/null"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-image-encryption", ["--enable-image-encryption"]),
                                                       CliOption::new("image-key", ["--image-key", "/dev/null"])])),

            // cck-available group tests: valid combinations
            // --enable-cck-extension-secret with --cck
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-cck-extension-secret", ["--enable-cck-extension-secret"]),
                                                       CliOption::new("cck", ["--cck", "/dev/null"])])),
            // --cck with --enable-cck-update (both cck-available options together)
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("cck", ["--cck", "/dev/null"]),
                                                       CliOption::new("enable-cck-update", ["--enable-cck-update"])])),
            // --enable-dump with --enable-cck-update (no --cck required as cck-update allows to set a CCK)
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-dump", ["--enable-dump"]),
                                                       CliOption::new("enable-cck-update", ["--enable-cck-update"])])),
            // --cck standalone (without any requiring options)
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("cck", ["--cck", "/dev/null"])])),
            // --comm-key with --enable-cck-update (alias test)
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("comm-key", ["--comm-key", "/dev/null"]),
                                                       CliOption::new("enable-cck-update", ["--enable-cck-update"])])),

            // --disable-flags tests
            // Test --disable-flags alone
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("disable-flags", ["--disable-flags", &SeHdrFlagName::PckmoHmac.to_string()])])),
            // Test --flags and --disable-flags without conflict
            flat_map_collect(insert(mvca.clone(), vec![
                CliOption::new("flags", ["--flags", &SeHdrFlagName::ConfidentialDump.to_string()]),
                CliOption::new("disable-flags", ["--disable-flags", &SeHdrFlagName::PckmoHmac.to_string()]),
                CliOption::new("cck", ["--cck", "/dev/null"])
            ])),
            // Test multiple --disable-flags
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("disable-flags", ["--disable-flags", &format!("{},{}", SeHdrFlagName::PckmoHmac, SeHdrFlagName::BackupTargetKeys)])])),
            // Test --flags and --disable-flags with different flags
            flat_map_collect(insert(mvca.clone(), vec![
                CliOption::new("flags", ["--flags", &format!("{},{}", SeHdrFlagName::ConfidentialDump, SeHdrFlagName::BackupTargetKeys)]),
                CliOption::new("disable-flags", ["--disable-flags", &format!("{},{}", SeHdrFlagName::PckmoHmac, SeHdrFlagName::NoComponentEncryption)]),
                CliOption::new("cck", ["--cck", "/dev/null"])
            ])),

            // --flags tests (equivalent to --enable-* tests)
            // Test --flags with confidential-dump (equivalent to --enable-dump)
            flat_map_collect(insert(mvca.clone(), vec![
                CliOption::new("flags", ["--flags", &SeHdrFlagName::ConfidentialDump.to_string()]),
                CliOption::new("cck", ["--cck", "/dev/null"])
            ])),

            // Test with --overwrite
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("overwrite", ["--overwrite"])])),

            // Test with --no-component-check
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("no-component-check", ["--no-component-check"])])),

            // Test with all PCKMO flags
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("flags", ["--flags", &format!("{},{},{},{}",
                                                                                                    SeHdrFlagName::PckmoDeaTdea, SeHdrFlagName::PckmoAes, SeHdrFlagName::PckmoEcc, SeHdrFlagName::PckmoHmac)])])),

            // Test with NoComponentEncryption flag
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("flags", ["--flags", &SeHdrFlagName::NoComponentEncryption.to_string()])])),

            // Test with HdrVersion V2
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("hdr-version", ["--hdr-version", "2"])])),
        ];
        // Invalid test cases grouped by expected error kind
        let invalid_missing_required = [
            flat_map_collect(remove(mvcanv.clone(), "no-verify")),
            flat_map_collect(remove(mvcanv.clone(), "image")),
            flat_map_collect(remove(mvcanv.clone(), "hkd")),
            flat_map_collect(remove(mvcanv, "output")),
            // missing both `--cck' and `--enable-cck-update' (required by --enable-dump)
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-dump", ["--enable-dump"])])),
            // Test --flags with confidential-dump but missing --cck (equivalent to --enable-dump without --cck)
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("flags", ["--flags", &SeHdrFlagName::ConfidentialDump.to_string()])])),
            // --enable-cck-extension-secret without cck-available (validation error, semantically missing required)
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-cck-extension-secret", ["--enable-cck-extension-secret"])])),
        ];

        let invalid_value = [
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("x-header-key", ["--hdr-key"]),])),
        ];

        let invalid_conflict = [
            // -v and -q cannot be combined
            flat_map_collect(insert(mvca.clone(), vec![
                CliOption::new("verbose", ["-v"]),
                CliOption::new("quiet", ["-q"])])),

            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("image2", ["--image", "/dev/null"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("output2", ["--output", "/dev/null"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("ramdisk", ["--ramdisk", "/dev/null"]),
                                                   CliOption::new("ramdisk2", ["--ramdisk", "/dev/null"]) ])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("parmfile", ["--parmfile", "/dev/null"]),
                                                   CliOption::new("parmfile2", ["--parmfile", "/dev/null"]) ])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("x-pcf", ["--x-pcf", "0x0"]),
                                                   CliOption::new("x-pcf2", ["--x-pcf", "0x0"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-pckmo", ["--enable-pckmo"]),
                                                   CliOption::new("disable-pckmo", ["--disable-pckmo"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-image-encryption", ["--enable-image-encryption"]),
                                                   CliOption::new("disable-image-encryption", ["--disable-image-encryption"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("extension", ["--enable-cck-extension-secret"]),
                                                   CliOption::new("update", ["--enable-cck-update"])])),

            // Image component key cannot be provided multiple times
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("x-comp-key", ["--x-comp-key", "/dev/null"]),
                                                       CliOption::new("x-comp-key2", ["--x-comp-key", "/dev/null"])])),
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("x-comp-key", ["--x-comp-key", "/dev/null"]),
                                                       CliOption::new("image-key", ["--image-key", "/dev/null"])])),

            // Disable image encryption and providing an image-key is mutually
            // exclusive.
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("disable-image-encryption", ["--disable-image-encryption"]),
                                                       CliOption::new("image-key", ["--image-key", "/dev/null"])])),

            // --enable-cck-extension-secret with --enable-cck-update and --cck (conflict takes precedence)
            flat_map_collect(insert(mvca.clone(), vec![CliOption::new("enable-cck-extension-secret", ["--enable-cck-extension-secret"]),
                                                       CliOption::new("enable-cck-update", ["--enable-cck-update"]),
                                                       CliOption::new("cck", ["--cck", "/dev/null"])])),

            // --disable-flags conflict tests
            // Test conflict between --flags and --disable-flags (same flag in both)
            flat_map_collect(insert(mvca.clone(), vec![
                CliOption::new("flags", ["--flags", &SeHdrFlagName::ConfidentialDump.to_string()]),
                CliOption::new("disable-flags", ["--disable-flags", &SeHdrFlagName::ConfidentialDump.to_string()]),
                CliOption::new("cck", ["--cck", "/dev/null"])
            ])),
            // Test multiple conflicts
            flat_map_collect(insert(mvca.clone(), vec![
                CliOption::new("flags", ["--flags", &format!("{},{}", SeHdrFlagName::ConfidentialDump, SeHdrFlagName::PckmoHmac)]),
                CliOption::new("disable-flags", ["--disable-flags", &format!("{},{}", SeHdrFlagName::ConfidentialDump, SeHdrFlagName::PckmoHmac)]),
                CliOption::new("cck", ["--cck", "/dev/null"])
            ])),

            // --flags conflicts with --x-pcf
            flat_map_collect(insert(mvca.clone(), vec![
                CliOption::new("flags", ["--flags", &SeHdrFlagName::ConfidentialDump.to_string()]),
                CliOption::new("x-pcf", ["--x-pcf", "0x0"]),
                CliOption::new("cck", ["--cck", "/dev/null"])
            ])),
            // --flags conflicts with --x-scf
            flat_map_collect(insert(mvca.clone(), vec![
                CliOption::new("flags", ["--flags", &SeHdrFlagName::ConfidentialDump.to_string()]),
                CliOption::new("x-scf", ["--x-scf", "0x0"]),
                CliOption::new("cck", ["--cck", "/dev/null"])
            ])),
            // --disable-flags conflicts with --x-pcf
            flat_map_collect(insert(mvca.clone(), vec![
                CliOption::new("disable-flags", ["--disable-flags", &SeHdrFlagName::PckmoHmac.to_string()]),
                CliOption::new("x-pcf", ["--x-pcf", "0x0"])
            ])),
            // --disable-flags conflicts with --x-scf
            flat_map_collect(insert(mvca.clone(), vec![
                CliOption::new("disable-flags", ["--disable-flags", &SeHdrFlagName::PckmoHmac.to_string()]),
                CliOption::new("x-scf", ["--x-scf", "0x0"])
            ])),

            // Test --flags with cck-extension-secret and cck-update and --cck
            // (conflict, equivalent to --enable-cck-extension-secret)
            flat_map_collect(insert(mvca, vec![
                CliOption::new("flags-cck-extension-secret", ["--flags", &SeHdrFlagName::CckExtensionSecretEnforcement.to_string()]),
                CliOption::new("flags-enable-cck-update", ["--flags", &SeHdrFlagName::CckUpdate.to_string()]),
                CliOption::new("cck", ["--cck", "/dev/null"])
            ])),
        ];

        let mut genprotimg_valid_args = vec![
            // See workaround `parse_version` in `pvimg/main.rs`.
            // vec!["genprotimg", "--version"],
        ];
        let mut pvimg_valid_args = vec![
            vec!["pvimg", "--version"],
            vec!["pvimg", "version"],
        ];

        // Test that `genprotimg` and `pvimg create` behave equally.
        for create_args in &valid_create_args {
            genprotimg_valid_args.push([["genprotimg"].to_vec(), Vec::from_iter(create_args.iter().map(String::as_str))].concat());
            pvimg_valid_args.push([["pvimg", "create"].to_vec(), Vec::from_iter(create_args.iter().map(String::as_str))].concat());
        }

        // Test invalid args with expected error kinds
        let test_cases = [
            (&invalid_missing_required[..], clap::error::ErrorKind::MissingRequiredArgument, "MissingRequiredArgument"),
            (&invalid_value[..], clap::error::ErrorKind::InvalidValue, "InvalidValue"),
            (&invalid_conflict[..], clap::error::ErrorKind::ArgumentConflict, "ArgumentConflict"),
        ];

        // Parse and convert functions for each CLI variant
        let parse_pvimg = |args: &[&str]| CliOptions::try_parse_from(args);
        // The into converts Result<GenprotimgCliOptions, Error> into Result<CliOptions, Error>
        let parse_genprotimg = |args: &[&str]| GenprotimgCliOptions::try_parse_from(args).map(Into::into);

        // Test both CLI variants
        for (name, valid_args, cmd_prefix, parse_fn) in [
            ("pvimg", pvimg_valid_args, &["pvimg", "create"] as &[&str], &parse_pvimg as &dyn Fn(&[&str]) -> Result<CliOptions, clap::Error>),
            ("genprotimg", genprotimg_valid_args, &["genprotimg"] as &[&str], &parse_genprotimg as &dyn Fn(&[&str]) -> Result<CliOptions, clap::Error>),
        ] {
            test_valid_args(valid_args, parse_fn, name);
            test_invalid_args(&test_cases, cmd_prefix, parse_fn, name);
        }
    }

    #[test]
    fn pvimg_test_cli() {
        let args = BTreeMap::new();
        let valid_test_args = [
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("host-key-hashes", ["--key-hashes"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("host-key-hashes2", ["--key-hashes=/dev/null"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("host-key-hashes2", ["--key-hashes=/dev/null"]),
                    CliOption::new("image", ["/dev/null"]),
                    // global works
                    CliOption::new("quiet", ["-q"]),
                ],
            )),
            // separation between keyword and positional args works
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("host-key-hashes2", ["--key-hashes=/dev/null"]),
                    CliOption::new("image", ["--", "/dev/null"]),
                ],
            )),
            // Verify that the old verbosity is still working.
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("host-key-hashes2", ["--key-hashes=/dev/null"]),
                    CliOption::new("image", ["/dev/null"]),
                    CliOption::new("verbose", ["-VVV"]),
                ],
            )),
            // Test with --host-key-document
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("host-key-document", ["--host-key-document", "/dev/null"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
            // Test with multiple --host-key-document (comma-separated)
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new(
                        "host-key-document",
                        ["--host-key-document", "/dev/null,/dev/zero"],
                    ),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
        ];

        // Invalid test cases grouped by expected error kind
        let invalid_missing_required = [
            // Missing required test-args group (only image provided, no host-key info)
            flat_map_collect(insert(
                args.clone(),
                vec![CliOption::new("image", ["/dev/null"])],
            )),
        ];

        let invalid_conflict = [
            // the argument '--key-hashes[=<FILE>]' cannot be used with '--host-key-document
            // <FILE>'
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("host-key-hashes2", ["--key-hashes=/dev/null"]),
                    CliOption::new("host-key-document", ["--host-key-document", "/dev/null"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
        ];

        let invalid_unknown_arg = [flat_map_collect(insert(
            args.clone(),
            vec![
                CliOption::new("host-key-hashes2", ["--key-hashes", "/sys/null"]),
                CliOption::new("image", ["--", "/dev/null"]),
            ],
        ))];

        let mut pvimg_valid_args = vec![];

        for create_args in &valid_test_args {
            pvimg_valid_args.push(
                [
                    ["pvimg", "test"].to_vec(),
                    Vec::from_iter(create_args.iter().map(String::as_str)),
                ]
                .concat(),
            );
        }

        let test_cases = [
            (
                &invalid_missing_required[..],
                clap::error::ErrorKind::MissingRequiredArgument,
                "MissingRequiredArgument",
            ),
            (
                &invalid_conflict[..],
                clap::error::ErrorKind::ArgumentConflict,
                "ArgumentConflict",
            ),
            (
                &invalid_unknown_arg[..],
                clap::error::ErrorKind::UnknownArgument,
                "UnknownArgument",
            ),
        ];

        let parse_pvimg = |args: &[&str]| CliOptions::try_parse_from(args);
        test_valid_args(
            pvimg_valid_args,
            &parse_pvimg as &dyn Fn(&[&str]) -> Result<CliOptions, clap::Error>,
            "pvimg test",
        );
        test_invalid_args(
            &test_cases,
            &["pvimg", "test"],
            &parse_pvimg as &dyn Fn(&[&str]) -> Result<CliOptions, clap::Error>,
            "pvimg test",
        );
    }

    #[test]
    fn pvimg_info_cli() {
        let args = BTreeMap::new();
        let valid_test_args = [
            // Format argument is optional
            flat_map_collect(insert(
                args.clone(),
                vec![CliOption::new("image", ["/dev/null"])],
            )),
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("format", ["--format", "json"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("format", ["--format=json"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("hdr-key", ["--hdr-key", "/dev/null"]),
                    CliOption::new("format", ["--format=json"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("hdr-key", ["--key", "/dev/null"]),
                    CliOption::new("format", ["--format=json"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("hdr-key", ["--key", "/dev/null"]),
                    CliOption::new("format", ["--format=json:default"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("hdr-key", ["--key", "/dev/null"]),
                    CliOption::new("format", ["--format=json:minify"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("hdr-key", ["--key", "/dev/null"]),
                    CliOption::new("format", ["--format=json:pretty"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
            // separation between keyword and positional args works
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("format", ["--format=json"]),
                    CliOption::new("image", ["--", "/dev/null"]),
                ],
            )),
            // Verify that the old verbosity is still working.
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("format", ["--format=json"]),
                    CliOption::new("image", ["/dev/null"]),
                    CliOption::new("verbose", ["-VVV"]),
                ],
            )),
            // --print-schema json works standalone
            flat_map_collect(insert(
                args.clone(),
                vec![CliOption::new(
                    "print-json-schema",
                    ["--print-schema", "json"],
                )],
            )),
            // --show-secrets with --hdr-key
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("hdr-key", ["--hdr-key", "/dev/null"]),
                    CliOption::new("show-secrets", ["--show-secrets"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
            // text:full format
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("format", ["--format", "text:full"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
        ];

        // Invalid test cases grouped by expected error kind
        let invalid_value = [
            // No default defined for --format
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("format", ["--format"]),
                    CliOption::new("image", ["--", "/dev/null"]),
                ],
            )),
        ];

        let invalid_conflict = [
            // --print-json-schema conflicts with input
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("print-json-schema", ["--print-schema", "json"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
            // --print-json-schema conflicts with --format
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("print-json-schema", ["--print-schema", "json"]),
                    CliOption::new("format", ["--format=json"]),
                ],
            )),
            // --print-json-schema conflicts with --hdr-key
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("print-json-schema", ["--print-schema", "json"]),
                    CliOption::new("hdr-key", ["--hdr-key", "/dev/null"]),
                ],
            )),
            // --print-json-schema conflicts with --show-secrets
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("print-json-schema", ["--print-schema", "json"]),
                    CliOption::new("show-secrets", ["--show-secrets"]),
                ],
            )),
        ];

        let mut pvimg_valid_args = vec![];

        for create_args in &valid_test_args {
            pvimg_valid_args.push(
                [
                    ["pvimg", "info"].to_vec(),
                    Vec::from_iter(create_args.iter().map(String::as_str)),
                ]
                .concat(),
            );
        }

        let invalid_format = [
            // Invalid format variant for text
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("format", ["--format", "text:minify"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
            // Invalid format variant for json
            flat_map_collect(insert(
                args.clone(),
                vec![
                    CliOption::new("format", ["--format", "json:full"]),
                    CliOption::new("image", ["/dev/null"]),
                ],
            )),
        ];

        let test_cases = [
            (
                &invalid_value[..],
                clap::error::ErrorKind::InvalidValue,
                "InvalidValue",
            ),
            (
                &invalid_conflict[..],
                clap::error::ErrorKind::ArgumentConflict,
                "ArgumentConflict",
            ),
            (
                &invalid_format[..],
                clap::error::ErrorKind::ValueValidation,
                "ValueValidation",
            ),
        ];

        let parse_pvimg = |args: &[&str]| CliOptions::try_parse_from(args);
        test_valid_args(
            pvimg_valid_args,
            &parse_pvimg as &dyn Fn(&[&str]) -> Result<CliOptions, clap::Error>,
            "pvimg info",
        );
        test_invalid_args(
            &test_cases,
            &["pvimg", "info"],
            &parse_pvimg as &dyn Fn(&[&str]) -> Result<CliOptions, clap::Error>,
            "pvimg info",
        );
    }

    #[test]
    fn test_hdr_version_conversions() {
        assert_eq!(HkdVersion::from(HdrVersion::V1), HkdVersion::Classical);
        assert_eq!(HkdVersion::from(HdrVersion::V2), HkdVersion::Hybrid);
    }

    #[test]
    fn test_output_format_kind_display() {
        assert_eq!(OutputFormatKind::Text.to_string(), "human-readable");
        assert_eq!(OutputFormatKind::Json.to_string(), "JSON");
    }

    #[test]
    fn test_output_format_kind_from_str() {
        assert_eq!(
            "text".parse::<OutputFormatKind>().unwrap(),
            OutputFormatKind::Text
        );
        assert_eq!(
            "json".parse::<OutputFormatKind>().unwrap(),
            OutputFormatKind::Json
        );
        assert!("invalid".parse::<OutputFormatKind>().is_err());
    }

    #[test]
    fn test_new_version_cmd_opts() {
        let opts = CliOptions::new_version_cmd_opts();
        assert!(opts.version);
        assert!(matches!(opts.cmd, SubCommands::Version));
    }

    #[test]
    fn test_genprotimg_to_cli_options_conversion() {
        let genprotimg_opts = GenprotimgCliOptions {
            args: Box::new(CreateBootImageArgs::default()),
            verbose: DeprecatedVerbosityOptions::default(),
            version: (),
            help_all: (),
            help_experimental: (),
        };
        let cli_opts: CliOptions = genprotimg_opts.into();
        assert!(!cli_opts.version);
        assert!(matches!(cli_opts.cmd, SubCommands::Create(_)));
    }

    #[test]
    fn test_se_hdr_flag_name_display() {
        assert_eq!(
            SeHdrFlagName::ConfidentialDump.to_string(),
            "confidential-dump"
        );
        assert_eq!(SeHdrFlagName::PckmoDeaTdea.to_string(), "pckmo-dea-tdea");
        assert_eq!(SeHdrFlagName::PckmoAes.to_string(), "pckmo-aes");
        assert_eq!(SeHdrFlagName::PckmoEcc.to_string(), "pckmo-ecc");
        assert_eq!(SeHdrFlagName::PckmoHmac.to_string(), "pckmo-hmac");
        assert_eq!(
            SeHdrFlagName::BackupTargetKeys.to_string(),
            "backup-target-keys"
        );
        assert_eq!(
            SeHdrFlagName::CckExtensionSecretEnforcement.to_string(),
            "cck-extension-secret-enforcement"
        );
        assert_eq!(SeHdrFlagName::CckUpdate.to_string(), "cck-update");
        assert_eq!(
            SeHdrFlagName::NoComponentEncryption.to_string(),
            "no-component-encryption"
        );
    }

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        CliOptions::command().debug_assert();
    }
}
