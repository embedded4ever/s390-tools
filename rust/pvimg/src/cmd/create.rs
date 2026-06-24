// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::fs::OpenOptions;
use std::io::BufReader;

use anyhow::{anyhow, Context, Result};
use log::{debug, info, warn};
use pv::misc::{open_file, try_parse_u64};
use pvimg::error::OwnExitCode;
use pvimg::secured_comp::ComponentTrait;
use pvimg::uvdata::{
    EffectiveControlFlags, FlagState, FlagsOverride, SeHdrControlFlags, SeHdrControlFlagsModel,
    SeHdrDataV1, SeHdrFlag, SeHdrVersion, SeTarget,
};
use utils::{AtomicFile, AtomicFileOperation};

use crate::cli::{ComponentPaths, CreateBootImageArgs, SeHdrFlagName};
use crate::cmd::common::read_user_provided_keys;
use crate::se_img::{SeHdrArgs, SeImgBuilder};
use crate::se_img_comps::cmdline::Cmdline;
use crate::se_img_comps::kernel::S390Kernel;
use crate::se_img_comps::ramdisk::Ramdisk;
use crate::se_img_comps::{check_components, Component};

/// Convert CLI flag name to internal SeHdrFlag
fn convert_flag_name(name: SeHdrFlagName) -> SeHdrFlag {
    match name {
        SeHdrFlagName::ConfidentialDump => SeHdrFlag::ConfidentialDump,
        SeHdrFlagName::PckmoDeaTdea => SeHdrFlag::PckmoDeaTdea,
        SeHdrFlagName::PckmoAes => SeHdrFlag::PckmoAes,
        SeHdrFlagName::PckmoEcc => SeHdrFlag::PckmoEcc,
        SeHdrFlagName::PckmoHmac => SeHdrFlag::PckmoHmac,
        SeHdrFlagName::BackupTargetKeys => SeHdrFlag::BackupTargetKeys,
        SeHdrFlagName::CckExtensionSecretEnforcement => SeHdrFlag::CckExtensionSecretEnforcement,
        SeHdrFlagName::CckUpdate => SeHdrFlag::CckUpdate,
        SeHdrFlagName::NoComponentEncryption => SeHdrFlag::NoComponentEncryption,
    }
}

/// The returned vector is sorted by the occurrence in the memory layout:
/// First the kernel, then the ramdisk and then the kernel cmdline.
///
/// Keep this ordering in sync with the ordering of [`ComponentKind`]!
fn components(component_args: &ComponentPaths) -> Result<Vec<Component>> {
    // IMPORTANT: Don't change the order of the components: kernel, ramdisk, and
    // then parmline! This is important since ALD, PLD and TLD is sorted by the
    // component address.
    let mut components: Vec<Component> =
        vec![S390Kernel::new(Box::new(BufReader::new(open_file(&component_args.kernel)?))).into()];
    if let Some(path) = &component_args.ramdisk {
        components.push(Ramdisk::new(Box::new(BufReader::new(open_file(path)?))).into());
    }
    if let Some(path) = &component_args.parmfile {
        components.push(Cmdline::new(Box::new(BufReader::new(open_file(path)?))).into());
    }
    Ok(components)
}

/// Parse new-style flags (--flags and --disable-flags)
fn parse_new_style_flags(
    flags: &[SeHdrFlagName],
    disable_flags: &[SeHdrFlagName],
    version: SeHdrVersion,
) -> Result<(FlagsOverride<SeHdrFlag>, FlagsOverride<SeHdrFlag>)> {
    let target = SeTarget::from_se_hdr_version(version);
    let mut pcf_overrides: FlagsOverride<SeHdrFlag> = FlagsOverride::new();
    let mut scf_overrides: FlagsOverride<SeHdrFlag> = FlagsOverride::new();

    if flags.is_empty() && disable_flags.is_empty() {
        return Ok((pcf_overrides, scf_overrides));
    }

    let pcf_model = SeHdrControlFlagsModel::pcf_for_target(target);
    let scf_model = SeHdrControlFlagsModel::scf_for_target(target);
    let pcf_supported = pcf_model.supported_flags();
    let scf_supported = scf_model.supported_flags();

    // Helper function to process flags
    let mut process_flags =
        |flag_list: &[SeHdrFlagName], enable: bool, flag_type: &str| -> Result<()> {
            if flag_list.is_empty() {
                return Ok(());
            }

            let converted_flags: Vec<SeHdrFlag> =
                flag_list.iter().map(|&f| convert_flag_name(f)).collect();

            for flag in &converted_flags {
                if pcf_supported.contains(flag) {
                    if enable {
                        pcf_overrides.enable(*flag);
                    } else {
                        pcf_overrides.disable(*flag);
                    }
                }
                if scf_supported.contains(flag) {
                    if enable {
                        scf_overrides.enable(*flag);
                    } else {
                        scf_overrides.disable(*flag);
                    }
                }
            }

            // Check if all flags were consumed (supported by either pcf or scf)
            let unsupported_flags: Vec<&SeHdrFlag> = converted_flags
                .iter()
                .filter(|flag| !pcf_supported.contains(flag) && !scf_supported.contains(flag))
                .collect();

            if !unsupported_flags.is_empty() {
                return Err(anyhow!(
                    "The following {} are not supported for SE header version {:?}: {:?}",
                    flag_type,
                    version,
                    unsupported_flags
                ));
            }

            Ok(())
        };

    process_flags(flags, true, "flags")?;
    process_flags(disable_flags, false, "disable flags")?;

    Ok((pcf_overrides, scf_overrides))
}

/// Parse legacy-style flags
fn parse_legacy_flags(
    legacy_flags: &crate::cli::CreateBootImageLegacyFlags,
) -> (FlagsOverride<SeHdrFlag>, FlagsOverride<SeHdrFlag>) {
    macro_rules! flag_disabled {
        ($cli_flag:expr, $control_flags:expr) => {
            $cli_flag.filter(|x| *x).map(|_| {
                let mut flags = FlagsOverride::new();
                flags.disable_all($control_flags);
                flags
            })
        };
    }
    macro_rules! flag_enabled {
        ($cli_flag:expr, $control_flags:expr) => {
            $cli_flag.filter(|x| *x).map(|_| {
                let mut flags = FlagsOverride::new();
                flags.enable_all($control_flags);
                flags
            })
        };
    }

    let pcf_overrides = [
        flag_disabled!(legacy_flags.disable_dump, [SeHdrFlag::ConfidentialDump]),
        flag_enabled!(legacy_flags.enable_dump, [SeHdrFlag::ConfidentialDump]),
        flag_disabled!(legacy_flags.disable_pckmo, SeHdrControlFlagsModel::PCKMO),
        flag_enabled!(legacy_flags.enable_pckmo, SeHdrControlFlagsModel::PCKMO),
        flag_disabled!(legacy_flags.disable_pckmo_hmac, [SeHdrFlag::PckmoHmac]),
        flag_enabled!(legacy_flags.enable_pckmo_hmac, [SeHdrFlag::PckmoHmac]),
        flag_disabled!(
            legacy_flags.disable_backup_keys,
            [SeHdrFlag::BackupTargetKeys]
        ),
        flag_enabled!(
            legacy_flags.enable_backup_keys,
            [SeHdrFlag::BackupTargetKeys]
        ),
        flag_enabled!(
            legacy_flags.disable_image_encryption,
            [SeHdrFlag::NoComponentEncryption]
        ),
        flag_disabled!(
            legacy_flags.enable_image_encryption,
            [SeHdrFlag::NoComponentEncryption]
        ),
    ]
    .into_iter()
    .flatten()
    .fold(FlagsOverride::new(), |mut acc, override_set| {
        for (flag, state) in override_set.iter() {
            match state {
                FlagState::Enabled => acc.enable(*flag),
                FlagState::Disabled => acc.disable(*flag),
            }
        }
        acc
    });

    let scf_overrides = [
        flag_disabled!(
            legacy_flags.disable_cck_extension_secret,
            [SeHdrFlag::CckExtensionSecretEnforcement]
        ),
        flag_enabled!(
            legacy_flags.enable_cck_extension_secret,
            [SeHdrFlag::CckExtensionSecretEnforcement]
        ),
        flag_disabled!(legacy_flags.disable_cck_update, [SeHdrFlag::CckUpdate]),
        flag_enabled!(legacy_flags.enable_cck_update, [SeHdrFlag::CckUpdate]),
    ]
    .into_iter()
    .flatten()
    .fold(FlagsOverride::new(), |mut acc, override_set| {
        for (flag, state) in override_set.iter() {
            match state {
                FlagState::Enabled => acc.enable(*flag),
                FlagState::Disabled => acc.disable(*flag),
            }
        }
        acc
    });

    (pcf_overrides, scf_overrides)
}

/// Apply experimental overrides to control flags
fn apply_experimental_overrides(
    pcf_overrides: &FlagsOverride<SeHdrFlag>,
    scf_overrides: &FlagsOverride<SeHdrFlag>,
    x_pcf: &Option<String>,
    x_scf: &Option<String>,
    target: SeTarget,
) -> Result<(
    EffectiveControlFlags<SeHdrFlag>,
    EffectiveControlFlags<SeHdrFlag>,
)> {
    let pcf = match x_pcf {
        Some(v) => {
            assert_eq!(pcf_overrides.len(), 0);
            SeHdrControlFlags::from_u64(try_parse_u64(v, "x-pcf")?, target, true)
        }
        None => SeHdrControlFlagsModel::pcf_for_target(target).with_overrides(pcf_overrides)?,
    };

    let scf = match x_scf {
        Some(v) => {
            assert_eq!(scf_overrides.len(), 0);
            SeHdrControlFlags::from_u64(try_parse_u64(v, "x-scf")?, target, false)
        }
        None => SeHdrControlFlagsModel::scf_for_target(target).with_overrides(scf_overrides)?,
    };

    Ok((pcf, scf))
}

fn parse_flags(
    args: &CreateBootImageArgs,
    version: SeHdrVersion,
) -> Result<(
    EffectiveControlFlags<SeHdrFlag>,
    EffectiveControlFlags<SeHdrFlag>,
)> {
    let target = SeTarget::from_se_hdr_version(version);

    // Legacy flags and --(disable-)flags are mutually exclusive. Clap semantics
    // is used for that.
    let (pcf_overrides, scf_overrides) = if args.flags.is_empty() && args.disable_flags.is_empty() {
        parse_legacy_flags(&args.legacy_flags)
    } else {
        parse_new_style_flags(&args.flags, &args.disable_flags, version)?
    };

    let (pcf, scf) = apply_experimental_overrides(
        &pcf_overrides,
        &scf_overrides,
        &args.experimental_args.x_pcf,
        &args.experimental_args.x_scf,
        target,
    )?;
    info!("Using plaintext flags:\n{pcf}");
    info!("Using secret flags:\n{scf}");

    Ok((pcf, scf))
}

/// Create a Secure Execution boot image
pub fn create(opt: &CreateBootImageArgs) -> Result<OwnExitCode> {
    // Verify host key documents first, because if they are not valid there is
    // no reason to continue.
    let verified_host_keys = opt
        .certificate_args
        .get_verified_hkds("Secure Execution image")?;
    let user_provided_keys = read_user_provided_keys(&opt.keys)?;
    let (plaintext_flags, secret_flags) = parse_flags(opt, SeHdrVersion::V1)?;

    if plaintext_flags.has(SeHdrFlag::NoComponentEncryption) {
        warn!("The components encryption is disabled, make sure that the components do not contain any confidential content.");
    }

    let mut components = components(&opt.component_paths)?;
    if opt.no_component_check {
        warn!("The component check is turned off!");
    } else {
        check_components(&mut components)?;
    }

    // FIXME get rid of the legacy mode. But that's only possible as soon as all
    // available tools are updated.
    let expected_se_hdr_size = SeHdrDataV1::expected_size(verified_host_keys.len())?;
    let mut writer = AtomicFile::with_extension(&opt.output, "part", &mut OpenOptions::new())?;
    let mut seimg_ctx = SeImgBuilder::new_v1(
        &mut writer,
        !plaintext_flags.has(SeHdrFlag::NoComponentEncryption),
        Some(expected_se_hdr_size),
        opt.experimental_args.x_bootloader_directory.as_ref(),
    )?;

    // Enable expert mode
    seimg_ctx.i_know_what_i_am_doing();
    if let Some((path, key)) = user_provided_keys.components_key {
        seimg_ctx.set_components_key(key).with_context(|| {
            format!(
                "Failed to use '{}' as the image components key",
                path.display()
            )
        })?;
    }

    let psw_addr: Option<u64> = match &opt.experimental_args.x_psw {
        Some(v) => try_parse_u64(v, "x-psw")?.into(),
        None => None,
    };

    for mut component in components.into_iter() {
        seimg_ctx
            .prepare_and_append_as_secure_component(&mut component, None)
            .with_context(|| format!("Failed to prepare {} component", component.kind()))?;
    }

    let img_comps = seimg_ctx.finish(SeHdrArgs {
        keys: verified_host_keys.as_slice(),
        pcf: &plaintext_flags,
        scf: &secret_flags,
        cck: &user_provided_keys.cck,
        hdr_aead_key: &user_provided_keys.aead_key,
        psw_addr: &psw_addr,
    })?;

    debug!("");
    debug!("----------------------------------------------------------------");
    debug!("| {:^60} |", "Secure Execution image layout");
    debug!("|--------------------------------------------------------------|");
    debug!("| {:<23} | {:<34} |", "Component type", "Component address");
    debug!("|-------------------------|------------------------------------|");
    img_comps
        .iter()
        .for_each(|img_comp| debug!("{img_comp:<33}"));
    debug!("----------------------------------------------------------------");

    // Rename the file `$OUTPUT.part` to `$OUTPUT` for achieving atomic file
    // creation.
    let op = match opt.overwrite {
        true => AtomicFileOperation::Replace,
        false => AtomicFileOperation::NoReplace,
    };
    writer.finish(op)?;

    warn!("Successfully generated the Secure Execution image.");
    Ok(OwnExitCode::Success)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cli::CreateBootImageLegacyFlags;

    #[test]
    fn parse_flags() {
        let args = CreateBootImageArgs {
            legacy_flags: CreateBootImageLegacyFlags {
                enable_dump: Some(true),
                enable_cck_update: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };
        let parsed_flags =
            super::parse_flags(&args, SeHdrVersion::V1).expect("Failed to parse flags {args:?}");

        // Build expected PCF
        let mut exp_pcf = Vec::from(SeHdrControlFlagsModel::PCKMO);
        exp_pcf.push(SeHdrFlag::ConfidentialDump);
        let mut pcf_overrides = FlagsOverride::new();
        for flag in &exp_pcf {
            pcf_overrides.enable(*flag);
        }
        let expected_pcf = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V1Max)
            .with_overrides(&pcf_overrides)
            .expect("Failed to create expected PCF");
        assert_eq!(parsed_flags.0, expected_pcf);

        // Build expected SCF
        let exp_scf = vec![SeHdrFlag::CckUpdate];
        let mut scf_overrides = FlagsOverride::new();
        for flag in &exp_scf {
            scf_overrides.enable(*flag);
        }
        let expected_scf = SeHdrControlFlagsModel::scf_for_target(SeTarget::V1Max)
            .with_overrides(&scf_overrides)
            .expect("Failed to create expected SCF");
        assert_eq!(parsed_flags.1, expected_scf);
    }

    #[test]
    fn parse_flags_with_disable_flags_no_conflict() {
        let args = CreateBootImageArgs {
            flags: vec![SeHdrFlagName::ConfidentialDump],
            disable_flags: vec![SeHdrFlagName::PckmoHmac],
            ..Default::default()
        };
        let result = super::parse_flags(&args, SeHdrVersion::V1);
        assert!(result.is_ok());

        let (pcf, scf) = result.unwrap();
        // ConfidentialDump should be enabled
        assert!(pcf.has(SeHdrFlag::ConfidentialDump));
        // PckmoHmac should be disabled
        assert!(!pcf.has(SeHdrFlag::PckmoHmac));
        assert_eq!(pcf.to_u64(), 0b100000000000000000000011100000_u64);
        assert_eq!(scf.to_u64(), 0b0_u64);
    }

    #[test]
    fn parse_flags_with_multiple_disable_flags() {
        let args = CreateBootImageArgs {
            disable_flags: vec![SeHdrFlagName::PckmoHmac, SeHdrFlagName::BackupTargetKeys],
            ..Default::default()
        };
        let result = super::parse_flags(&args, SeHdrVersion::V1);
        assert!(result.is_ok());

        let (pcf, _scf) = result.unwrap();
        // Both flags should be disabled
        assert!(!pcf.has(SeHdrFlag::PckmoHmac));
        assert!(!pcf.has(SeHdrFlag::BackupTargetKeys));
    }

    #[test]
    fn parse_flags_with_only_disable_flags() {
        let args = CreateBootImageArgs {
            disable_flags: vec![SeHdrFlagName::PckmoDeaTdea, SeHdrFlagName::PckmoAes],
            ..Default::default()
        };
        let result = super::parse_flags(&args, SeHdrVersion::V1);
        assert!(result.is_ok());

        let (pcf, _scf) = result.unwrap();
        // PCKMO DEA/TDEA and AES should be disabled
        assert!(!pcf.has(SeHdrFlag::PckmoDeaTdea));
        assert!(!pcf.has(SeHdrFlag::PckmoAes));
    }

    #[test]
    fn parse_flags_enable_and_disable_different_flags() {
        let args = CreateBootImageArgs {
            flags: vec![
                SeHdrFlagName::ConfidentialDump,
                SeHdrFlagName::BackupTargetKeys,
            ],
            disable_flags: vec![
                SeHdrFlagName::PckmoHmac,
                SeHdrFlagName::NoComponentEncryption,
            ],
            ..Default::default()
        };
        let result = super::parse_flags(&args, SeHdrVersion::V1);
        assert!(result.is_ok());

        let (pcf, _scf) = result.unwrap();
        // Enabled flags should be set
        assert!(pcf.has(SeHdrFlag::ConfidentialDump));
        assert!(pcf.has(SeHdrFlag::BackupTargetKeys));
        // Disabled flags should not be set
        assert!(!pcf.has(SeHdrFlag::PckmoHmac));
        assert!(!pcf.has(SeHdrFlag::NoComponentEncryption));
    }
}
