// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.

//! Control flags for Secure Execution (SE) headers.
//!
//! This module provides a flexible, type-safe API for managing control flags used in
//! IBM Secure Execution (SE) headers. It supports both plaintext and secret control flags
//! with version-specific configurations.
//!
//! # Architecture
//!
//! The module is built around several key components:
//!
//! ## Core Types
//!
//! - [`SeHdrFlag`] - Unified enum containing all control flags (plaintext and secret)
//! - [`SeHdrControlFlagsModel`] - Version-specific configuration model that defines:
//!   - Which flags are supported in a given SE header version
//!   - Which flags are enabled by default
//! - [`FlagsOverride`] - Container for user-specified flag overrides (enable/disable)
//! - [`FlagState`] - Represents whether a flag is enabled or disabled
//!
//! ## Traits
//!
//! - [`ControlFlagTrait`] - Core trait for flag types, providing:
//!   - `bit_position()` - Returns the bit position in the control flags bitfield
//!   - `enabled()`/`disabled()` - Create flag data with specific states
//!   - `AsRef<Self>` - Enables flexible API usage with both owned and borrowed values
//!
//! - [`IntoEnumIterator`] - Enables iteration over all flag variants
//!
//! # Usage Patterns
//!
//! ## 1. Getting Version-Specific Configuration
//!
//! ```rust
//! use pvimg::uvdata::{SeHdrControlFlagsModel, SeTarget};
//!
//! // Get plaintext control flags configuration for V1-max
//! let pcf_v1 = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V1Max);
//!
//! // Get secret control flags configuration for V2-max
//! let scf_v2 = SeHdrControlFlagsModel::scf_for_target(SeTarget::V2Max);
//! ```
//!
//! ## 2. Checking Flag Support and Defaults
//!
//! ```rust
//! use pvimg::uvdata::{SeHdrControlFlagsModel, SeHdrFlag, SeTarget};
//!
//! let pcf_v1 = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V1Max);
//!
//! // Check if a flag is supported in this target
//! assert!(pcf_v1.supports(SeHdrFlag::ConfidentialDump));
//!
//! // Check if a flag is enabled by default
//! assert!(pcf_v1.is_default(SeHdrFlag::PckmoAes));
//! assert!(!pcf_v1.is_default(SeHdrFlag::ConfidentialDump));
//! ```
//!
//! ## 3. Applying Overrides
//!
//! ```rust
//! use pvimg::uvdata::{FlagsOverride, SeHdrControlFlagsModel, SeHdrFlag, SeTarget};
//!
//! let pcf_v1 = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V1Max);
//!
//! // Create overrides to customize flags
//! let mut overrides = FlagsOverride::new();
//! overrides.enable(SeHdrFlag::ConfidentialDump);
//! overrides.disable(SeHdrFlag::PckmoAes);
//!
//! // Validate and apply overrides
//! let result = pcf_v1.with_overrides(&overrides);
//! assert!(result.is_ok());
//! ```
//!
//! ## 4. Working with Flag Collections
//!
//! ```rust
//! use pvimg::uvdata::{SeHdrControlFlagsModel, SeTarget};
//!
//! let pcf_v2 = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V2Max);
//!
//! // Get all supported flags
//! let supported = pcf_v2.supported_flags();
//! println!("V2-max supports {} plaintext flags", supported.len());
//!
//! // Get default flags
//! let defaults = pcf_v2.default_flags();
//! println!("V2-max has {} default plaintext flags", defaults.len());
//! ```
//!
//! # Version Differences
//!
//! ## Plaintext Control Flags
//!
//! **V1 Defaults:** `PckmoDeaTdea`, `PckmoAes`, `PckmoEcc`
//!
//! **V2 Defaults:** `PckmoDeaTdea`, `PckmoAes`, `PckmoEcc`, `PckmoHmac`
//!
//! ## Secret Control Flags
//!
//! **V1 & V2:** Both versions support `CckExtensionSecretEnforcement` and `CckUpdate`
//! (no defaults, must be explicitly enabled via overrides)
//!
//! # Error Handling
//!
//! The API uses [`FlagValidationError`] to report issues:
//!
//! - `NotSupported` - Attempted to override a flag not supported in the target version
//!
//! ```

use std::collections::HashSet;

use pv::misc::{Flags, Msb0Flags64};
use utils::ControlFlag;

// Re-export IntoEnumIterator for external use
pub use super::generic_flags::IntoEnumIterator;
// Re-export generic types and traits from generic_flags module
pub use super::generic_flags::{
    ControlFlagTrait, ControlFlagsModel, EffectiveControlFlags, FlagData, FlagState, FlagsOverride,
    SeTarget, UnknownFlags,
};

pub type SeHdrControlFlags = EffectiveControlFlags<SeHdrFlag>;

impl SeHdrControlFlags {
    /// Creates an `EffectiveControlFlags<SeHdrFlag>` from a u64 value for the specified target.
    ///
    /// # Arguments
    ///
    /// * `value` - The u64 bitfield value
    /// * `target` - The target SE header flags configuration
    /// * `is_pcf` - Whether this is for plaintext control flags (true) or secret control flags
    ///   (false)
    ///
    /// # Returns
    ///
    /// An `EffectiveControlFlags<SeHdrFlag>` with flags extracted from the u64 value
    pub fn from_u64(value: u64, target: SeTarget, is_pcf: bool) -> Self {
        let flags = Msb0Flags64::from(value);
        let target_model = if is_pcf {
            SeHdrControlFlagsModel::pcf_for_target(target)
        } else {
            SeHdrControlFlagsModel::scf_for_target(target)
        };

        // Parse the flags and extract known flags
        let mut known_flags = HashSet::new();
        let mut unhandled_bits = flags;

        for flag in SeHdrFlag::iter() {
            if flags.is_set(flag.bit_position()) && target_model.supports(flag) {
                known_flags.insert(flag);
                // Clear this bit from unhandled
                unhandled_bits.unset_bit(flag.bit_position());
            }
        }

        EffectiveControlFlags::new(
            target.to_se_hdr_version(),
            known_flags,
            UnknownFlags::from_bits(unhandled_bits),
        )
    }
}

/// Type alias for plaintext control flags configuration.
pub type SeHdrControlFlagsModel = ControlFlagsModel<SeHdrFlag>;

impl SeHdrControlFlagsModel {
    /// Array of all PCKMO-related flags (excluding HMAC).
    pub const PCKMO: [SeHdrFlag; 3] = [
        SeHdrFlag::PckmoDeaTdea,
        SeHdrFlag::PckmoAes,
        SeHdrFlag::PckmoEcc,
    ];

    /// Creates a new PlaintextControlFlags for the specified SE header flags target with predefined
    /// defaults.
    pub fn pcf_for_target(target: SeTarget) -> Self {
        use SeHdrFlag::*;

        // Common flags for both V1 and V2
        let common_supported = [
            ConfidentialDump,
            NoComponentEncryption,
            PckmoDeaTdea,
            PckmoAes,
            PckmoEcc,
            PckmoHmac,
            BackupTargetKeys,
        ];
        let common_defaults = [PckmoDeaTdea, PckmoAes, PckmoEcc];

        let (default, supported) = match target {
            SeTarget::V1Max => (
                common_defaults.into_iter().collect(),
                common_supported.into_iter().collect(),
            ),
            SeTarget::V2Max => (
                common_defaults.into_iter().chain([PckmoHmac]).collect(),
                common_supported.into_iter().chain([]).collect(),
            ),
        };

        Self::new(target, default, supported)
    }

    /// Creates a new SecretControlFlags for the specified SE header flags target with predefined
    /// defaults.
    pub fn scf_for_target(target: SeTarget) -> Self {
        use SeHdrFlag::*;

        let supported = [CckExtensionSecretEnforcement, CckUpdate]
            .into_iter()
            .collect();
        let default = HashSet::new();

        Self::new(target, default, supported)
    }
}

/// Control Flags - All possible flags across all versions.
///
/// This enum contains all control flags (both plaintext and secret) that can be used across
/// different SE header versions.
#[derive(ControlFlag, Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum SeHdrFlag {
    #[flag(display = "CCK extension secret enforced", value = 1)]
    /// Enforces extension secret requirement for add-secret requests.
    ///
    /// When set, all add-secret requests must provide an extension secret.
    /// This adds an additional layer of security to secret management.
    CckExtensionSecretEnforcement,

    #[flag(display = "CCK update allowed", value = 2)]
    /// Allows Customer Communication Key (CCK) updates.
    ///
    /// When set, permits updating the CCK after initial configuration.
    CckUpdate,

    #[flag(display = "confidential guest dump support", value = 34)]
    /// Enables Confidential guest dump support.
    ///
    /// When set, allows dumping of the Secure Execution guest for debugging purposes.
    ConfidentialDump,

    #[flag(display = "no component encryption", value = 35)]
    /// Disables component encryption during image unpacking.
    ///
    /// When set, components are not decrypted during the SE image unpack process.
    NoComponentEncryption,

    #[flag(display = "DEA and TDEA PCKMO support", value = 56)]
    /// Enables DEA/TDEA PCKMO encryption functions.
    ///
    /// Allows the guest to use Data Encryption Algorithm (DEA) and Triple DEA
    /// with the Perform Cryptographic Key Management Operation (PCKMO) instruction.
    PckmoDeaTdea,

    #[flag(display = "AES PCKMO support", value = 57)]
    /// Enables AES PCKMO encryption functions.
    ///
    /// Allows the guest to use Advanced Encryption Standard (AES) with PCKMO.
    PckmoAes,

    #[flag(display = "ECC PCKMO support", value = 58)]
    /// Enables ECC PCKMO encryption functions.
    ///
    /// Allows the guest to use Elliptic Curve Cryptography (ECC) with PCKMO.
    PckmoEcc,

    #[flag(display = "HMAC PCKMO support", value = 59)]
    /// Enables HMAC PCKMO encryption functions.
    ///
    /// Allows the guest to use Hash-based Message Authentication Code (HMAC) with PCKMO.
    PckmoHmac,

    #[flag(display = "backup target keys support", value = 62)]
    /// Enables backup target keys support.
    ///
    /// When set, allows the use of backup target keys for key management operations.
    BackupTargetKeys,
}

// Implement AsRef<Self> for SeHdrFlag to enable flexible API usage
impl AsRef<SeHdrFlag> for SeHdrFlag {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl std::str::FromStr for SeHdrFlag {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s.to_lowercase().replace('_', "-");

        // Try to find a flag whose display name matches the input
        for flag in Self::iter() {
            let display_name = format!("{}", flag).to_lowercase().replace(' ', "-");

            // Check for exact match with display name
            if normalized == display_name {
                return Ok(flag);
            }

            // Check for common abbreviations
            let matches = match flag {
                Self::PckmoDeaTdea => normalized == "pckmo-dea-tdea" || normalized == "pckmo-dea",
                Self::BackupTargetKeys => {
                    normalized == "backup-keys" || normalized == "backup-target-keys"
                }
                Self::CckExtensionSecretEnforcement => {
                    normalized == "cck-extension-secret"
                        || normalized == "cck-extension-secret-enforcement"
                }
                Self::CckUpdate => normalized == "cck-update" || normalized == "cck-update-allowed",
                _ => false,
            };

            if matches {
                return Ok(flag);
            }
        }

        Err(format!("Unknown flag name: '{}'", s))
    }
}

#[allow(clippy::shadow_unrelated)]
#[cfg(test)]
mod test {
    use pv::misc::Flags;

    use super::super::brb::SeHdrVersion;
    use super::*;

    #[test]
    fn test_pcfs_v1() {
        let pcfs_v1 = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V1Max);

        // V1 flags
        assert!(pcfs_v1.supports(SeHdrFlag::ConfidentialDump));
        assert!(pcfs_v1.supports(SeHdrFlag::NoComponentEncryption));
        assert!(pcfs_v1.supports(SeHdrFlag::PckmoDeaTdea));
        assert!(pcfs_v1.supports(SeHdrFlag::PckmoAes));
        assert!(pcfs_v1.supports(SeHdrFlag::PckmoEcc));
        assert!(pcfs_v1.supports(SeHdrFlag::PckmoHmac));
        assert!(pcfs_v1.supports(SeHdrFlag::BackupTargetKeys));

        // Check defaults (PCKMO flags)
        assert!(pcfs_v1.is_default(SeHdrFlag::PckmoDeaTdea));
        assert!(pcfs_v1.is_default(SeHdrFlag::PckmoAes));
        assert!(pcfs_v1.is_default(SeHdrFlag::PckmoEcc));
        assert!(!pcfs_v1.is_default(SeHdrFlag::ConfidentialDump));
    }

    #[test]
    fn test_pcfs_v2() {
        let pcfs_v2 = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V2Max);

        // V1 flags (should all be supported in V2)
        assert!(pcfs_v2.supports(SeHdrFlag::ConfidentialDump));
        assert!(pcfs_v2.supports(SeHdrFlag::NoComponentEncryption));
        assert!(pcfs_v2.supports(SeHdrFlag::PckmoDeaTdea));
        assert!(pcfs_v2.supports(SeHdrFlag::PckmoAes));
        assert!(pcfs_v2.supports(SeHdrFlag::PckmoEcc));
        assert!(pcfs_v2.supports(SeHdrFlag::PckmoHmac));
        assert!(pcfs_v2.supports(SeHdrFlag::BackupTargetKeys));

        // Check defaults (same as V1)
        assert!(pcfs_v2.is_default(SeHdrFlag::PckmoDeaTdea));
        assert!(pcfs_v2.is_default(SeHdrFlag::PckmoAes));
        assert!(pcfs_v2.is_default(SeHdrFlag::PckmoEcc));
    }

    #[test]
    fn test_scfs_v1() {
        let scfs_v1 = SeHdrControlFlagsModel::scf_for_target(SeTarget::V1Max);

        assert!(scfs_v1.supports(SeHdrFlag::CckExtensionSecretEnforcement));
        assert!(scfs_v1.supports(SeHdrFlag::CckUpdate));

        // No defaults for secret flags
        assert!(!scfs_v1.is_default(SeHdrFlag::CckExtensionSecretEnforcement));
        assert!(!scfs_v1.is_default(SeHdrFlag::CckUpdate));
    }

    #[test]
    fn test_scfs_v2() {
        let scfs_v2 = SeHdrControlFlagsModel::scf_for_target(SeTarget::V2Max);

        assert!(scfs_v2.supports(SeHdrFlag::CckExtensionSecretEnforcement));
        assert!(scfs_v2.supports(SeHdrFlag::CckUpdate));
    }

    #[test]
    fn test_scfs_v1_with_overrides() {
        // Create base model for V1 secret control flags
        let scf_v1 = SeHdrControlFlagsModel::scf_for_target(SeTarget::V1Max);

        // Verify defaults are empty
        assert!(scf_v1.default_flags().is_empty());

        // Create overrides to enable specific flags
        let mut overrides = FlagsOverride::new();
        overrides.enable_all([
            SeHdrFlag::CckExtensionSecretEnforcement,
            SeHdrFlag::CckUpdate,
        ]);

        // Verify overrides were set
        assert_eq!(overrides.len(), 2);
        assert!(overrides.has_override(SeHdrFlag::CckExtensionSecretEnforcement));
        assert!(overrides.has_override(SeHdrFlag::CckUpdate));
        assert_eq!(
            overrides.get(SeHdrFlag::CckExtensionSecretEnforcement),
            Some(FlagState::Enabled)
        );
        assert_eq!(
            overrides.get(SeHdrFlag::CckUpdate),
            Some(FlagState::Enabled)
        );

        // Apply overrides to get configured model
        let configured_scf = scf_v1
            .with_overrides(&overrides)
            .expect("Valid overrides should succeed");

        // Verify the configured model still has the same version and supported flags
        assert_eq!(configured_scf.version(), SeHdrVersion::V1);
        assert_eq!(configured_scf.known_flags().len(), 2);
        assert!(configured_scf.has(SeHdrFlag::CckExtensionSecretEnforcement));
        assert!(configured_scf.has(SeHdrFlag::CckUpdate));
    }

    #[test]
    fn test_scfs_v1_partial_overrides() {
        // Create base model for V1 secret control flags
        let scf_v1 = SeHdrControlFlagsModel::scf_for_target(SeTarget::V1Max);

        // Create overrides to enable only one flag
        let mut overrides = FlagsOverride::new();
        overrides.enable(SeHdrFlag::CckExtensionSecretEnforcement);

        // Verify only one override was set
        assert_eq!(overrides.len(), 1);
        assert!(overrides.has_override(SeHdrFlag::CckExtensionSecretEnforcement));
        assert!(!overrides.has_override(SeHdrFlag::CckUpdate));

        // Apply overrides
        let configured_scf = scf_v1
            .with_overrides(&overrides)
            .expect("Valid overrides should succeed");

        // Verify the configured model maintains version and support
        assert_eq!(configured_scf.version(), SeHdrVersion::V1);
        assert!(configured_scf.has(SeHdrFlag::CckExtensionSecretEnforcement));
        assert!(!configured_scf.has(SeHdrFlag::CckUpdate));
    }

    #[test]
    fn test_pcfs_v1_with_overrides_enable_additional() {
        // Create base model for V1 plaintext control flags
        let pcf_v1 = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V1Max);

        // Verify V1 defaults: PckmoDeaTdea, PckmoAes, PckmoEcc (but NOT PckmoHmac)
        assert_eq!(pcf_v1.default_flags().len(), 3);
        assert!(pcf_v1.is_default(SeHdrFlag::PckmoDeaTdea));
        assert!(pcf_v1.is_default(SeHdrFlag::PckmoAes));
        assert!(pcf_v1.is_default(SeHdrFlag::PckmoEcc));
        assert!(!pcf_v1.is_default(SeHdrFlag::PckmoHmac));
        assert!(!pcf_v1.is_default(SeHdrFlag::ConfidentialDump));

        // Create overrides to enable additional flags
        let mut overrides = FlagsOverride::new();
        overrides.enable_all([SeHdrFlag::PckmoHmac, SeHdrFlag::ConfidentialDump]);

        // Verify overrides were set
        assert_eq!(overrides.len(), 2);
        assert!(overrides.has_override(SeHdrFlag::PckmoHmac));
        assert!(overrides.has_override(SeHdrFlag::ConfidentialDump));
        assert_eq!(
            overrides.get(SeHdrFlag::PckmoHmac),
            Some(FlagState::Enabled)
        );
        assert_eq!(
            overrides.get(SeHdrFlag::ConfidentialDump),
            Some(FlagState::Enabled)
        );

        // Apply overrides to get configured model
        let configured_pcf = pcf_v1
            .with_overrides(&overrides)
            .expect("Valid overrides should succeed");

        // Verify the configured model maintains version and support
        assert_eq!(configured_pcf.version(), SeHdrVersion::V1);
        assert!(configured_pcf.has(SeHdrFlag::PckmoHmac));
        assert!(configured_pcf.has(SeHdrFlag::ConfidentialDump));
    }

    #[test]
    fn test_pcfs_v1_with_overrides_disable_defaults() {
        // Create base model for V1 plaintext control flags
        let pcf_v1 = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V1Max);

        // Verify V1 defaults include PckmoAes and PckmoEcc
        assert!(pcf_v1.is_default(SeHdrFlag::PckmoAes));
        assert!(pcf_v1.is_default(SeHdrFlag::PckmoEcc));

        // Create overrides to disable some default flags
        let mut overrides = FlagsOverride::new();
        overrides.disable_all([SeHdrFlag::PckmoAes, SeHdrFlag::PckmoEcc]);

        // Verify overrides were set to disabled
        assert_eq!(overrides.len(), 2);
        assert_eq!(
            overrides.get(SeHdrFlag::PckmoAes),
            Some(FlagState::Disabled)
        );
        assert_eq!(
            overrides.get(SeHdrFlag::PckmoEcc),
            Some(FlagState::Disabled)
        );

        // Apply overrides to get configured model
        let configured_pcf = pcf_v1
            .with_overrides(&overrides)
            .expect("Valid overrides should succeed");

        // Verify the configured model maintains version and support
        assert_eq!(configured_pcf.version(), SeHdrVersion::V1);
        assert!(!configured_pcf.has(SeHdrFlag::PckmoAes));
        assert!(!configured_pcf.has(SeHdrFlag::PckmoEcc));
    }

    #[test]
    fn test_pcfs_v2_with_overrides_mixed() {
        // Create base model for V2 plaintext control flags
        let pcf_v2 = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V2Max);

        // Verify V2 defaults: PckmoDeaTdea, PckmoAes, PckmoEcc, PckmoHmac
        assert_eq!(pcf_v2.default_flags().len(), 4);
        assert!(pcf_v2.is_default(SeHdrFlag::PckmoDeaTdea));
        assert!(pcf_v2.is_default(SeHdrFlag::PckmoAes));
        assert!(pcf_v2.is_default(SeHdrFlag::PckmoEcc));
        assert!(pcf_v2.is_default(SeHdrFlag::PckmoHmac));

        // Create mixed overrides: disable one default, enable one non-default
        let mut overrides = FlagsOverride::new();
        overrides.disable(SeHdrFlag::PckmoHmac); // Disable a default
        overrides.enable(SeHdrFlag::NoComponentEncryption); // Enable a non-default

        // Verify overrides
        assert_eq!(overrides.len(), 2);
        assert_eq!(
            overrides.get(SeHdrFlag::PckmoHmac),
            Some(FlagState::Disabled)
        );
        assert_eq!(
            overrides.get(SeHdrFlag::NoComponentEncryption),
            Some(FlagState::Enabled)
        );

        // Apply overrides
        let configured_pcf = pcf_v2
            .with_overrides(&overrides)
            .expect("Valid overrides should succeed");

        // Verify the configured model maintains version and support
        assert_eq!(configured_pcf.version(), SeHdrVersion::V2);
        assert!(!configured_pcf.has(SeHdrFlag::PckmoHmac));
        assert!(configured_pcf.has(SeHdrFlag::NoComponentEncryption));
    }

    #[test]
    fn test_asref_flexibility() {
        // Test that both owned values and references work with AsRef-based API
        let pcf_v1 = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V1Max);

        // Using references (explicit)
        assert!(pcf_v1.supports(SeHdrFlag::PckmoAes));
        assert!(pcf_v1.is_default(SeHdrFlag::PckmoAes));

        // Using owned values (also works thanks to AsRef)
        assert!(pcf_v1.supports(SeHdrFlag::PckmoAes));
        assert!(pcf_v1.is_default(SeHdrFlag::PckmoAes));

        assert!(!pcf_v1.is_default(SeHdrFlag::ConfidentialDump));
        assert!(!pcf_v1.is_default(SeHdrFlag::ConfidentialDump));
    }

    #[test]
    fn test_with_overrides_supported_flags_succeed() {
        // Create V1 model
        let pcf_v1 = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V1Max);

        // Enable only supported flags
        let mut overrides = FlagsOverride::new();
        overrides.enable_all([SeHdrFlag::ConfidentialDump, SeHdrFlag::PckmoHmac]);

        // Should succeed
        let result = pcf_v1.with_overrides(&overrides);
        assert!(result.is_ok());

        let configured = result.unwrap();
        assert_eq!(configured.version(), SeHdrVersion::V1);
    }

    #[test]
    fn test_overrides_update_existing() {
        // Test that enable/disable update existing overrides (canonical way)
        let mut overrides = FlagsOverride::new();

        // Initially enable a flag
        overrides.enable(SeHdrFlag::PckmoAes);
        assert_eq!(overrides.get(SeHdrFlag::PckmoAes), Some(FlagState::Enabled));
        assert_eq!(overrides.len(), 1);

        // Update the same flag to disabled (canonical way)
        overrides.disable(SeHdrFlag::PckmoAes);
        assert_eq!(
            overrides.get(SeHdrFlag::PckmoAes),
            Some(FlagState::Disabled)
        );
        assert_eq!(overrides.len(), 1); // Still only one override

        // Update again to enabled (canonical way)
        overrides.enable(SeHdrFlag::PckmoAes);
        assert_eq!(overrides.get(SeHdrFlag::PckmoAes), Some(FlagState::Enabled));
        assert_eq!(overrides.len(), 1); // Still only one override

        // Add a different flag
        overrides.enable(SeHdrFlag::PckmoEcc);
        assert_eq!(overrides.len(), 2); // Now we have two overrides

        // Update the first flag again
        overrides.disable(SeHdrFlag::PckmoAes);
        assert_eq!(
            overrides.get(SeHdrFlag::PckmoAes),
            Some(FlagState::Disabled)
        );
        assert_eq!(overrides.get(SeHdrFlag::PckmoEcc), Some(FlagState::Enabled));
        assert_eq!(overrides.len(), 2); // Still two overrides

        // Alternative: set() can also be used but enable/disable are preferred
        overrides.set(SeHdrFlag::PckmoAes, FlagState::Enabled);
        assert_eq!(overrides.get(SeHdrFlag::PckmoAes), Some(FlagState::Enabled));
        assert_eq!(overrides.len(), 2); // Still two overrides
    }

    #[test]
    fn test_plaintext_control_flags_construction_v1() {
        // Test construction of PlaintextControlFlags for V1
        let pcf_v1 = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V1Max);

        // Verify version
        assert_eq!(pcf_v1.version(), SeHdrVersion::V1);

        // Verify default flags for V1
        let default_flags = pcf_v1.default_flags();
        assert_eq!(default_flags.len(), 3);
        assert!(default_flags.contains(&SeHdrFlag::PckmoDeaTdea));
        assert!(default_flags.contains(&SeHdrFlag::PckmoAes));
        assert!(default_flags.contains(&SeHdrFlag::PckmoEcc));
        assert!(!default_flags.contains(&SeHdrFlag::PckmoHmac));

        // Verify supported flags for V1
        let supported_flags = pcf_v1.supported_flags();
        assert_eq!(supported_flags.len(), 7);
        assert!(supported_flags.contains(&SeHdrFlag::ConfidentialDump));
        assert!(supported_flags.contains(&SeHdrFlag::NoComponentEncryption));
        assert!(supported_flags.contains(&SeHdrFlag::PckmoDeaTdea));
        assert!(supported_flags.contains(&SeHdrFlag::PckmoAes));
        assert!(supported_flags.contains(&SeHdrFlag::PckmoEcc));
        assert!(supported_flags.contains(&SeHdrFlag::PckmoHmac));
        assert!(supported_flags.contains(&SeHdrFlag::BackupTargetKeys));
    }

    #[test]
    fn test_plaintext_control_flags_construction_v2() {
        // Test construction of PlaintextControlFlags for V2
        let pcf_v2 = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V2Max);

        // Verify version
        assert_eq!(pcf_v2.version(), SeHdrVersion::V2);

        // Verify default flags for V2
        let default_flags = pcf_v2.default_flags();
        assert_eq!(default_flags.len(), 4);
        assert!(default_flags.contains(&SeHdrFlag::PckmoDeaTdea));
        assert!(default_flags.contains(&SeHdrFlag::PckmoAes));
        assert!(default_flags.contains(&SeHdrFlag::PckmoEcc));
        assert!(default_flags.contains(&SeHdrFlag::PckmoHmac));

        // Verify supported flags for V2
        let supported_flags = pcf_v2.supported_flags();
        assert_eq!(supported_flags.len(), 7);
        assert!(supported_flags.contains(&SeHdrFlag::ConfidentialDump));
        assert!(supported_flags.contains(&SeHdrFlag::NoComponentEncryption));
        assert!(supported_flags.contains(&SeHdrFlag::PckmoDeaTdea));
        assert!(supported_flags.contains(&SeHdrFlag::PckmoAes));
        assert!(supported_flags.contains(&SeHdrFlag::PckmoEcc));
        assert!(supported_flags.contains(&SeHdrFlag::PckmoHmac));
        assert!(supported_flags.contains(&SeHdrFlag::BackupTargetKeys));
    }

    #[test]
    fn test_secret_control_flags_construction_v1() {
        // Test construction of SecretControlFlags for V1
        let scf_v1 = SeHdrControlFlagsModel::scf_for_target(SeTarget::V1Max);

        // Verify version
        assert_eq!(scf_v1.version(), SeHdrVersion::V1);

        // Verify default flags for V1 (should be empty)
        let default_flags = scf_v1.default_flags();
        assert_eq!(default_flags.len(), 0);
        assert!(default_flags.is_empty());

        // Verify supported flags for V1
        let supported_flags = scf_v1.supported_flags();
        assert_eq!(supported_flags.len(), 2);
        assert!(supported_flags.contains(&SeHdrFlag::CckExtensionSecretEnforcement));
        assert!(supported_flags.contains(&SeHdrFlag::CckUpdate));
    }

    #[test]
    fn test_secret_control_flags_construction_v2() {
        // Test construction of SecretControlFlags for V2
        let scf_v2 = SeHdrControlFlagsModel::scf_for_target(SeTarget::V2Max);

        // Verify version
        assert_eq!(scf_v2.version(), SeHdrVersion::V2);

        // Verify default flags for V2 (should be empty)
        let default_flags = scf_v2.default_flags();
        assert_eq!(default_flags.len(), 0);
        assert!(default_flags.is_empty());

        // Verify supported flags for V2 (same as V1)
        let supported_flags = scf_v2.supported_flags();
        assert_eq!(supported_flags.len(), 2);
        assert!(supported_flags.contains(&SeHdrFlag::CckExtensionSecretEnforcement));
        assert!(supported_flags.contains(&SeHdrFlag::CckUpdate));
    }

    #[test]
    fn test_plaintext_flags_v1_vs_v2_differences() {
        let pcf_v1 = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V1Max);
        let pcf_v2 = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V2Max);

        // V1 should have 3 default flags, V2 should have 4
        assert_eq!(pcf_v1.default_flags().len(), 3);
        assert_eq!(pcf_v2.default_flags().len(), 4);

        // V2 adds PckmoHmac to defaults
        assert!(!pcf_v1.is_default(SeHdrFlag::PckmoHmac));
        assert!(pcf_v2.is_default(SeHdrFlag::PckmoHmac));

        // V1 should have 7 supported flags, V2 should have 7 [TODO: Marc claims 8?]
        assert_eq!(pcf_v1.supported_flags().len(), 7);
        assert_eq!(pcf_v2.supported_flags().len(), 7);
    }

    #[test]
    fn test_secret_flags_v1_vs_v2_consistency() {
        let scf_v1 = SeHdrControlFlagsModel::scf_for_target(SeTarget::V1Max);
        let scf_v2 = SeHdrControlFlagsModel::scf_for_target(SeTarget::V2Max);

        // Both versions should have the same defaults (empty)
        assert_eq!(scf_v1.default_flags().len(), scf_v2.default_flags().len());
        assert!(scf_v1.default_flags().is_empty());
        assert!(scf_v2.default_flags().is_empty());

        // Both versions should have the same supported flags
        assert_eq!(
            scf_v1.supported_flags().len(),
            scf_v2.supported_flags().len()
        );
        assert_eq!(scf_v1.supported_flags(), scf_v2.supported_flags());
    }
    // Tests for Into<Msb0Flags64> trait implementations

    #[test]
    fn test_into_msb0_flags_owned() {
        // Test Into<Msb0Flags64> for owned ControlFlagsModel
        let pcf_v1 = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V1Max);

        // V1 defaults: PckmoDeaTdea, PckmoAes, PckmoEcc
        let flags: Msb0Flags64 = pcf_v1.into();

        // Verify the default flags are set
        assert!(flags.is_set(SeHdrFlag::PckmoDeaTdea.bit_position()));
        assert!(flags.is_set(SeHdrFlag::PckmoAes.bit_position()));
        assert!(flags.is_set(SeHdrFlag::PckmoEcc.bit_position()));

        // Verify non-default flags are not set
        assert!(!flags.is_set(SeHdrFlag::PckmoHmac.bit_position()));
        assert!(!flags.is_set(SeHdrFlag::ConfidentialDump.bit_position()));
    }

    #[test]
    fn test_into_msb0_flags_borrowed() {
        // Test Into<Msb0Flags64> for borrowed ControlFlagsModel
        let pcf_v2 = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V2Max);

        // Convert using reference (model remains usable)
        let flags: Msb0Flags64 = (&pcf_v2).into();

        // V2 defaults: PckmoDeaTdea, PckmoAes, PckmoEcc, PckmoHmac
        assert!(flags.is_set(SeHdrFlag::PckmoDeaTdea.bit_position()));
        assert!(flags.is_set(SeHdrFlag::PckmoAes.bit_position()));
        assert!(flags.is_set(SeHdrFlag::PckmoEcc.bit_position()));
        assert!(flags.is_set(SeHdrFlag::PckmoHmac.bit_position()));

        // Model should still be usable
        assert_eq!(pcf_v2.version(), SeHdrVersion::V2);
        assert_eq!(pcf_v2.default_flags().len(), 4);
    }

    #[test]
    fn test_to_msb0_flags_with_overrides() {
        let pcf_v1 = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V1Max);

        // Create overrides
        let mut overrides = FlagsOverride::new();
        overrides.enable(SeHdrFlag::ConfidentialDump);
        overrides.disable(SeHdrFlag::PckmoAes);

        let flags: Msb0Flags64 = pcf_v1.with_overrides(&overrides).unwrap().into();
        // Verify overrides were applied
        assert!(flags.is_set(SeHdrFlag::ConfidentialDump.bit_position()));
        assert!(!flags.is_set(SeHdrFlag::PckmoAes.bit_position()));

        // Verify other defaults remain
        assert!(flags.is_set(SeHdrFlag::PckmoDeaTdea.bit_position()));
        assert!(flags.is_set(SeHdrFlag::PckmoEcc.bit_position()));
    }

    #[test]
    fn test_bit_position() {
        // Verify bit_position returns expected values
        assert_eq!(SeHdrFlag::CckExtensionSecretEnforcement.bit_position(), 1);
        assert_eq!(SeHdrFlag::CckUpdate.bit_position(), 2);
        assert_eq!(SeHdrFlag::ConfidentialDump.bit_position(), 34);
        assert_eq!(SeHdrFlag::NoComponentEncryption.bit_position(), 35);
        assert_eq!(SeHdrFlag::PckmoDeaTdea.bit_position(), 56);
        assert_eq!(SeHdrFlag::PckmoAes.bit_position(), 57);
        assert_eq!(SeHdrFlag::PckmoEcc.bit_position(), 58);
        assert_eq!(SeHdrFlag::PckmoHmac.bit_position(), 59);
        assert_eq!(SeHdrFlag::BackupTargetKeys.bit_position(), 62);
    }

    #[test]
    fn test_asref_trait() {
        // Test that AsRef<Self> works for flags
        let flag = SeHdrFlag::PckmoAes;
        let flag_ref: &SeHdrFlag = flag.as_ref();
        assert_eq!(*flag_ref, flag);
    }

    // Tests for from_u64 method

    #[test]
    fn test_effective_control_flags_from_u64_pcf_v1() {
        // Test creating EffectiveControlFlags from u64 for PCF V1
        let mut value = 0u64;
        // Set some PCF V1 flags
        value |= 1u64 << (63 - SeHdrFlag::ConfidentialDump.bit_position());
        value |= 1u64 << (63 - SeHdrFlag::PckmoAes.bit_position());
        value |= 1u64 << (63 - SeHdrFlag::PckmoDeaTdea.bit_position());

        let flags = SeHdrControlFlags::from_u64(value, SeTarget::V1Max, true);

        assert_eq!(flags.version(), SeHdrVersion::V1);
        assert!(flags.has(SeHdrFlag::ConfidentialDump));
        assert!(flags.has(SeHdrFlag::PckmoAes));
        assert!(flags.has(SeHdrFlag::PckmoDeaTdea));
        assert!(!flags.has(SeHdrFlag::PckmoHmac)); // Not set
    }

    #[test]
    fn test_effective_control_flags_from_u64_scf_v1() {
        // Test creating EffectiveControlFlags from u64 for SCF V1
        let mut value = 0u64;
        // Set some SCF V1 flags
        value |= 1u64 << (63 - SeHdrFlag::CckExtensionSecretEnforcement.bit_position());
        value |= 1u64 << (63 - SeHdrFlag::CckUpdate.bit_position());

        let flags = SeHdrControlFlags::from_u64(value, SeTarget::V1Max, false);

        assert_eq!(flags.version(), SeHdrVersion::V1);
        assert!(flags.has(SeHdrFlag::CckExtensionSecretEnforcement));
        assert!(flags.has(SeHdrFlag::CckUpdate));
    }

    #[test]
    fn test_effective_control_flags_from_u64_with_unknown_bits() {
        // Test that unknown/unsupported bits are tracked
        let mut value = 0u64;
        // Set a known flag
        value |= 1u64 << (63 - SeHdrFlag::PckmoAes.bit_position());
        // Set some unknown bits
        value |= 1u64 << 10; // Random bit that's not a known flag

        let flags = SeHdrControlFlags::from_u64(value, SeTarget::V1Max, true);

        assert!(flags.has(SeHdrFlag::PckmoAes));
        // Unknown flags should be tracked
        assert_ne!(flags.unknown_flags().bits(), 0);
    }

    #[test]
    fn test_effective_control_flags_from_u64_roundtrip() {
        // Test roundtrip: create flags, convert to u64, convert back
        let mut value = 0u64;
        value |= 1u64 << (63 - SeHdrFlag::ConfidentialDump.bit_position());
        value |= 1u64 << (63 - SeHdrFlag::PckmoAes.bit_position());
        value |= 1u64 << (63 - SeHdrFlag::BackupTargetKeys.bit_position());

        let flags1 = SeHdrControlFlags::from_u64(value, SeTarget::V1Max, true);
        let value2 = flags1.to_u64();
        let flags2 = SeHdrControlFlags::from_u64(value2, SeTarget::V1Max, true);

        assert_eq!(flags1.known_flags(), flags2.known_flags());
        assert_eq!(flags1.unknown_flags(), flags2.unknown_flags());
    }

    #[test]
    fn test_effective_control_flags_from_u64_empty() {
        // Test with no flags set
        let value = 0u64;
        let flags = SeHdrControlFlags::from_u64(value, SeTarget::V1Max, true);

        assert_eq!(flags.version(), SeHdrVersion::V1);
        assert_eq!(flags.known_flags().len(), 0);
        assert_eq!(flags.unknown_flags().bits(), 0);
    }

    #[test]
    fn test_effective_control_flags_from_u64_v2_specific() {
        // Test V2-specific flags
        let mut value = 0u64;
        value |= 1u64 << (63 - SeHdrFlag::PckmoHmac.bit_position());

        let flags = SeHdrControlFlags::from_u64(value, SeTarget::V2Max, true);

        assert_eq!(flags.version(), SeHdrVersion::V2);
        assert!(flags.has(SeHdrFlag::PckmoHmac));
    }
}
