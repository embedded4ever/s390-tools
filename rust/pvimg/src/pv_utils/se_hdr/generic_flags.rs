// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.

//! Generic control flags infrastructure for Secure Execution (SE) headers.
//!
//! This module provides the generic, reusable components for managing control flags
//! in IBM Secure Execution headers. It defines traits, generic types, and implementations
//! that can work with any flag enum type.
//!
//! # Core Components
//!
//! ## Traits
//!
//! - [`ControlFlagTrait`] - Core trait that flag enums must implement
//! - [`IntoEnumIterator`] - Enables iteration over flag enum variants
//! - [`IntoBitPosition`] - Converts types to bit positions
//!
//! ## Generic Types
//!
//! - [`ControlFlagsModel<T>`] - Version-specific configuration model
//! - [`EffectiveControlFlags<T>`] - Final flags after applying overrides
//! - [`FlagsOverride<T>`] - Container for user-specified overrides
//! - [`FlagData<T>`] - Pairs a flag with its state
//! - [`UnknownFlags`] - Tracks unknown/unsupported flag bits
//!
//! ## Supporting Types
//!
//! - [`FlagState`] - Enabled or Disabled state
//! - [`FlagValidationError<T>`] - Validation errors
//! - [`Msb0FlagsConversionError<T>`] - Conversion errors
//!
//! # Usage
//!
//! This module is not typically used directly. Instead, use the concrete implementations
//! in the [`flags`](super::flags) module which provide `SeHdrFlag`, `SeHdrControlFlagsModel`,
//! and related types built on top of this generic infrastructure.

use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display};
use std::hash::Hash;

use pv::misc::{Flags, Msb0Flags64};

use super::brb::SeHdrVersion;

#[derive(Debug)]
pub enum FlagValidationError<T: ControlFlagTrait> {
    UnknownFlag(),
    NotSupported { model: &'static str, flag: T },
}

impl<T: ControlFlagTrait> Display for FlagValidationError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlagValidationError::UnknownFlag() => write!(f, "Unknown flag"),
            FlagValidationError::NotSupported { model, flag } => {
                write!(f, "Flag '{}' is not supported in {}", flag, model)
            }
        }
    }
}

impl<T: ControlFlagTrait> std::error::Error for FlagValidationError<T> {}

/// Secure Execution target configuration.
///
/// Specifies the target environment for which a Secure Execution boot image is being created.
/// This enum allows selecting the appropriate control flags and configuration based on the
/// target machine generation or SE header version.
///
/// # Current Usage
///
/// Currently, this enum is primarily used for selecting control flags configurations.
/// The target determines which control flags are available and their default values.
///
/// # Purpose
///
/// The target determines:
/// - Which control flags are available and their default values
/// - The SE header format version to use
/// - Compatibility with specific machine generations (future use)
///
/// # Future Extensibility
///
/// This design allows for future expansion when multiple variants of V1 or V2 configurations
/// may exist.
///
/// # Examples
///
/// ```
/// use pvimg::uvdata::{SeHdrControlFlagsModel, SeTarget};
///
/// // Select latest V1 configuration for newest features
/// let target = SeTarget::V1Max;
///
/// // Use target to get appropriate control flags
/// let pcf = SeHdrControlFlagsModel::pcf_for_target(target);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SeTarget {
    /// Latest V1 configuration.
    ///
    /// Targets the most recent V1 SE header format with all available V1 control flags.
    /// Use this for maximum compatibility with older machine generations that support V1.
    V1Max,

    /// Latest V2 configuration.
    ///
    /// Targets the most recent V2 SE header format with all available V2 control flags.
    /// Use this for newest features and machine generations that support V2.
    V2Max,
}

impl SeTarget {
    /// Converts the target to the corresponding SeHdrVersion.
    pub fn to_se_hdr_version(self) -> SeHdrVersion {
        match self {
            SeTarget::V1Max => SeHdrVersion::V1,
            SeTarget::V2Max => SeHdrVersion::V2,
        }
    }

    /// Creates a target from a SeHdrVersion.
    pub fn from_se_hdr_version(version: SeHdrVersion) -> Self {
        match version {
            SeHdrVersion::V1 => SeTarget::V1Max,
            SeHdrVersion::V2 => SeTarget::V2Max,
        }
    }
}

impl Display for SeTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeTarget::V1Max => write!(f, "V1-max"),
            SeTarget::V2Max => write!(f, "V2-max"),
        }
    }
}

pub trait IntoEnumIterator {
    /// Returns an iterator over all variants of this enum.
    fn iter() -> impl Iterator<Item = Self>;
}

/// Trait for individual control flag types.
///
/// This trait defines the interface for control flag enums, providing methods
/// to get the flag's bit position and create enabled/disabled flag data.
pub trait ControlFlagTrait:
    Debug + Hash + Copy + Eq + Ord + Display + IntoEnumIterator + AsRef<Self>
{
    /// Returns the bit position of this flag.
    ///
    /// The bit position determines where this flag is set in the control flags bitfield.
    fn bit_position(self) -> u8;

    /// Creates flag data with this flag in the enabled state.
    fn enabled(self) -> FlagData<Self> {
        FlagData::new(self, FlagState::Enabled)
    }

    /// Creates flag data with this flag in the disabled state.
    fn disabled(self) -> FlagData<Self> {
        FlagData::new(self, FlagState::Disabled)
    }
}

/// Internal state of a control flag (enabled or disabled).
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum FlagState {
    /// Flag is enabled (bit set to 1)
    Enabled,
    /// Flag is disabled (bit set to 0)
    Disabled,
}

/// Represents a control flag with its associated state.
///
/// This structure pairs a flag with its enabled/disabled state, used when
/// constructing or modifying `ControlFlags` instances.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct FlagData<T: ControlFlagTrait> {
    value: T,
    state: FlagState,
}

impl<T: ControlFlagTrait> FlagData<T> {
    const fn new(value: T, state: FlagState) -> Self {
        Self { value, state }
    }
}

/// Generic flags configuration for a specific SE header flags target.
///
/// Contains the default and supported flags for a given target version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlFlagsModel<T: ControlFlagTrait> {
    target: SeTarget,
    default: HashSet<T>,
    supported: HashSet<T>,
}

impl<T: ControlFlagTrait> ControlFlagsModel<T> {
    /// Creates a new Flags configuration.
    pub(super) fn new(target: SeTarget, default: HashSet<T>, supported: HashSet<T>) -> Self {
        Self {
            target,
            default,
            supported,
        }
    }

    /// Returns the SE header flags target.
    pub fn target(&self) -> SeTarget {
        self.target
    }

    /// Returns the SE header version corresponding to this target.
    pub fn version(&self) -> SeHdrVersion {
        self.target.to_se_hdr_version()
    }

    /// Returns the set of default flags for this version.
    pub fn default_flags(&self) -> &HashSet<T> {
        &self.default
    }

    /// Returns the set of supported flags for this version.
    pub fn supported_flags(&self) -> &HashSet<T> {
        &self.supported
    }

    /// Checks if a flag is supported in this version.
    pub fn supports<F: AsRef<T>>(&self, flag: F) -> bool {
        self.supported.contains(flag.as_ref())
    }

    /// Checks if a flag is a default flag in this version.
    #[must_use]
    pub fn is_default<F: AsRef<T>>(&self, flag: F) -> bool {
        self.default.contains(flag.as_ref())
    }

    /// Validates that all flags in the overrides are supported by this model.
    ///
    /// # Arguments
    ///
    /// * `overrides` - The overrides to validate
    ///
    /// # Errors
    ///
    /// Returns `FlagValidationError::NotSupported` if any override flag is not supported by this
    /// model
    pub fn validate_overrides(
        &self,
        overrides: &FlagsOverride<T>,
    ) -> Result<(), FlagValidationError<T>> {
        for (flag, _state) in overrides.iter() {
            if !self.supports(flag) {
                return Err(FlagValidationError::NotSupported {
                    model: std::any::type_name::<T>(),
                    flag: *flag,
                });
            }
        }
        Ok(())
    }

    /// Applies overrides to the default flags and returns the effective control flags.
    ///
    /// This method validates the overrides, applies them to the default flags, and returns
    /// an `EffectiveControlFlags` instance containing the resulting configuration.
    ///
    /// # Arguments
    ///
    /// * `overrides` - Overrides to apply to the default flags
    ///
    /// # Returns
    ///
    /// An `EffectiveControlFlags<T>` instance with the effective flags after applying overrides
    ///
    /// # Errors
    ///
    /// Returns `FlagValidationError::NotSupported` if an override flag is not supported by this
    /// model
    pub fn with_overrides(
        &self,
        overrides: &FlagsOverride<T>,
    ) -> Result<EffectiveControlFlags<T>, FlagValidationError<T>> {
        // Validate overrides first
        self.validate_overrides(overrides)?;
        let mut effective_flags = self.default.clone();

        // Apply overrides
        for (flag, state) in overrides.iter() {
            match state {
                FlagState::Enabled => {
                    effective_flags.insert(*flag);
                }
                FlagState::Disabled => {
                    effective_flags.remove(flag);
                }
            }
        }

        Ok(EffectiveControlFlags {
            version: self.version(),
            known_flags: effective_flags,
            unknown_flags: UnknownFlags::empty(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownFlags(Msb0Flags64);

/// Trait for types that can be converted to a bit position.
pub trait IntoBitPosition {
    fn into_bit_position(self) -> u8;
}

/// Implement IntoBitPosition for u8 directly
impl IntoBitPosition for u8 {
    fn into_bit_position(self) -> u8 {
        self
    }
}

/// Implement IntoBitPosition for types that implement ControlFlagTrait
impl<T: ControlFlagTrait> IntoBitPosition for T {
    fn into_bit_position(self) -> u8 {
        self.bit_position()
    }
}

impl UnknownFlags {
    pub fn empty() -> Self {
        Self(Msb0Flags64::from(0u64))
    }

    pub fn from_bits(bits: Msb0Flags64) -> Self {
        Self(bits)
    }

    pub fn bits(self) -> u64 {
        self.0.into()
    }

    #[must_use]
    pub fn is_empty(self) -> bool {
        self.bits() == 0
    }

    /// Checks if a specific flag or bit position is set in the unknown flags.
    ///
    /// # Arguments
    ///
    /// * `flag` - Either a flag that implements `ControlFlagTrait`, a reference to such a flag, or
    ///   a raw bit position (u8)
    ///
    /// # Returns
    ///
    /// `true` if the bit position is set in the unknown flags, `false` otherwise
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Using a raw bit position
    /// unknown_flags.contains(5u8);
    /// ```
    #[must_use]
    pub fn contains(&self, position: u8) -> bool {
        self.0.is_set(position)
    }
}

/// Represents the effective control flags after applying overrides.
///
/// This structure contains the final set of flags that will be used, including both
/// known flags (from the model) and any unknown flags that were present in the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveControlFlags<T: ControlFlagTrait> {
    version: SeHdrVersion,
    known_flags: HashSet<T>,
    unknown_flags: UnknownFlags,
}

impl<T: ControlFlagTrait> EffectiveControlFlags<T> {
    /// Creates a new EffectiveControlFlags instance.
    ///
    /// This is primarily used internally by the flags module.
    pub(super) fn new(
        version: SeHdrVersion,
        known_flags: HashSet<T>,
        unknown_flags: UnknownFlags,
    ) -> Self {
        Self {
            version,
            known_flags,
            unknown_flags,
        }
    }

    /// Returns the SE header version.
    pub fn version(&self) -> SeHdrVersion {
        self.version
    }

    /// Returns the set of known flags.
    pub fn known_flags(&self) -> &HashSet<T> {
        &self.known_flags
    }

    /// Returns the unknown flags.
    pub fn unknown_flags(&self) -> UnknownFlags {
        self.unknown_flags
    }

    /// Checks if a flag or bit position is enabled in the effective flags.
    ///
    /// This method accepts either a flag type or a raw bit position (u8).
    ///
    /// # Arguments
    ///
    /// * `position` - Either a flag that implements `ControlFlagTrait`, a reference to such a flag,
    ///   or a raw bit position (u8)
    ///
    /// # Returns
    ///
    /// `true` if the flag/bit is enabled, `false` otherwise
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Using a flag
    /// flags.has(SeHdrFlag::PckmoAes);
    ///
    /// // Using a raw bit position
    /// flags.has(5u8);
    /// ```
    pub fn has<P: IntoBitPosition>(&self, position: P) -> bool {
        let bit_pos = position.into_bit_position();

        // Check if any known flag has this bit position
        for flag in &self.known_flags {
            if flag.bit_position() == bit_pos {
                return true;
            }
        }

        // Check unknown flags
        self.unknown_flags.contains(bit_pos)
    }

    /// Converts the effective flags to a u64 value.
    ///
    /// # Returns
    ///
    /// A u64 representation combining both known and unknown flags
    pub fn to_u64(&self) -> u64 {
        let flags: Msb0Flags64 = self.into();
        flags.into()
    }
}

/// Converts `EffectiveControlFlags` to `Msb0Flags64`.
///
/// This combines both known and unknown flags into a single bitfield.
impl<T: ControlFlagTrait> From<EffectiveControlFlags<T>> for Msb0Flags64 {
    fn from(flags: EffectiveControlFlags<T>) -> Self {
        let mut value = Msb0Flags64::from(flags.unknown_flags.bits());
        for flag in &flags.known_flags {
            value.set_bit(flag.bit_position());
        }
        value
    }
}

/// Converts a reference to `EffectiveControlFlags` to `Msb0Flags64`.
impl<T: ControlFlagTrait> From<&EffectiveControlFlags<T>> for Msb0Flags64 {
    fn from(flags: &EffectiveControlFlags<T>) -> Self {
        let mut value = Msb0Flags64::from(flags.unknown_flags.bits());
        for flag in &flags.known_flags {
            value.set_bit(flag.bit_position());
        }
        value
    }
}

/// Display implementation for `EffectiveControlFlags<T>`.
///
/// Provides two display formats:
/// - Normal format: Lists all enabled flags with " - " prefix, one per line
/// - Alternate format (`{:#}`): Shows the raw bitfield as 66-character binary string
///
/// # Examples
///
/// ```rust
/// use pvimg::uvdata::{FlagsOverride, SeHdrControlFlagsModel, SeHdrFlag, SeTarget};
///
/// let pcf_v1 = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V1Max);
/// let mut overrides = FlagsOverride::new();
/// overrides.enable(SeHdrFlag::ConfidentialDump);
/// let effective = pcf_v1.with_overrides(&overrides).unwrap();
///
/// // Normal format - lists enabled flags
/// println!("{}", effective);
///
/// // Alternate format - shows binary representation
/// println!("{:#}", effective);
/// ```
impl<T: ControlFlagTrait> Display for EffectiveControlFlags<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            // Alternate format: show as binary
            let flags: Msb0Flags64 = self.into();
            write!(f, "{:#066b}", <u64>::from(flags))
        } else {
            // Normal format: list enabled flags
            let flags_s: Vec<String> = self
                .known_flags
                .iter()
                .map(|flag| format!(" - {flag}"))
                .collect();

            if flags_s.is_empty() && self.unknown_flags.is_empty() {
                write!(f, "(no flags enabled)")
            } else {
                let mut output = flags_s.join("\n");
                if !self.unknown_flags.is_empty() {
                    if !output.is_empty() {
                        output.push('\n');
                    }
                    output.push_str(&format!(
                        " - unknown flags: {:#018x}",
                        self.unknown_flags.bits()
                    ));
                }
                write!(f, "{}", output)
            }
        }
    }
}

/// Converts a reference to `ControlFlagsModel` to `EffectiveControlFlags` using default flags.
///
/// This implementation allows conversion without consuming the model.
///
/// # Examples
///
/// ```rust
/// use pvimg::uvdata::{EffectiveControlFlags, SeHdrControlFlagsModel, SeTarget};
///
/// let pcf_v1 = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V1Max);
/// let flags: EffectiveControlFlags<_> = (&pcf_v1).into();
/// // pcf_v1 is still usable here
/// ```
impl<T: ControlFlagTrait> From<&ControlFlagsModel<T>> for EffectiveControlFlags<T> {
    fn from(model: &ControlFlagsModel<T>) -> Self {
        EffectiveControlFlags {
            version: model.version(),
            known_flags: model.default.clone(),
            unknown_flags: UnknownFlags::empty(),
        }
    }
}

/// Converts `ControlFlagsModel` to `Msb0Flags64` using default flags.
///
/// This consumes the model and converts it to a bitfield representation.
impl<T: ControlFlagTrait> From<ControlFlagsModel<T>> for Msb0Flags64 {
    fn from(model: ControlFlagsModel<T>) -> Self {
        let mut value = Msb0Flags64::default();
        for flag in &model.default {
            value.set_bit(flag.bit_position());
        }
        value
    }
}

/// Converts a reference to `ControlFlagsModel` to `Msb0Flags64` using default flags.
///
/// This implementation allows conversion without consuming the model.
impl<T: ControlFlagTrait> From<&ControlFlagsModel<T>> for Msb0Flags64 {
    fn from(model: &ControlFlagsModel<T>) -> Self {
        let mut value = Msb0Flags64::default();
        for flag in &model.default {
            value.set_bit(flag.bit_position());
        }
        value
    }
}
/// Display implementation for `ControlFlagsModel<T>`.
///
/// Provides two display formats:
/// - Normal format: Lists all default (enabled) flags with " - " prefix, one per line
/// - Alternate format (`{:#}`): Shows the raw bitfield as 66-character binary string
///
/// Note: This displays only the flags in the model's `default` set. Unknown flags
/// are not tracked by `ControlFlagsModel` - they are returned separately by
/// `from_msb0_flags()` when parsing raw bitfields.
///
/// # Examples
///
/// ```rust
/// use pvimg::uvdata::{SeHdrControlFlagsModel, SeTarget};
///
/// let pcf_v1 = SeHdrControlFlagsModel::pcf_for_target(SeTarget::V1Max);
///
/// // Normal format - lists default flags
/// println!("{}", pcf_v1);
///
/// // Alternate format - shows binary representation
/// println!("{:#}", pcf_v1);
/// ```
impl<T: ControlFlagTrait> Display for ControlFlagsModel<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            // Alternate format: show as binary
            let flags: Msb0Flags64 = self.into();
            write!(f, "{:#066b}", <u64>::from(flags))
        } else {
            // Normal format: list default (enabled) flags
            let flags_s: Vec<String> = self
                .default
                .iter()
                .map(|flag| format!(" - {flag}"))
                .collect();

            if flags_s.is_empty() {
                write!(f, "(no flags enabled)")
            } else {
                write!(f, "{}", flags_s.join("\n"))
            }
        }
    }
}

/// Error type for `TryFrom<Msb0Flags64>` conversion.
#[derive(Debug)]
// Will be used in an upcoming commit
#[expect(dead_code)]
pub enum Msb0FlagsConversionError<T: ControlFlagTrait> {
    /// A flag bit is set that is not supported in any version
    UnsupportedFlag { bit_position: u8 },
    /// A flag bit is set that is not supported in the specified version
    NotSupportedInVersion { flag: T, version: SeHdrVersion },
}

impl<T: ControlFlagTrait> Display for Msb0FlagsConversionError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedFlag { bit_position } => {
                write!(f, "Unsupported flag at bit position {}", bit_position)
            }
            Self::NotSupportedInVersion { flag, version } => {
                write!(f, "Flag {} not supported in version {:?}", flag, version)
            }
        }
    }
}

impl<T: ControlFlagTrait> std::error::Error for Msb0FlagsConversionError<T> {}

/// Override configuration for control flags.
///
/// Allows specifying individual flag states that override the default configuration.
/// This is useful for customizing flag settings on a per-flag basis.
///
/// # Type Parameters
///
/// * `T` - The control flag enum type (e.g., [`Flag`])
///
/// # Examples
///
/// ```rust
/// use pvimg::uvdata::{FlagsOverride, SeHdrFlag};
///
/// let mut overrides = FlagsOverride::new();
/// overrides.enable(SeHdrFlag::ConfidentialDump);
/// overrides.disable(SeHdrFlag::PckmoAes);
/// ```
#[derive(Debug, Clone)]
pub struct FlagsOverride<T: ControlFlagTrait> {
    overrides: HashMap<T, FlagState>,
}

impl<T: ControlFlagTrait> FlagsOverride<T> {
    /// Creates a new empty FlagsOverride.
    pub fn new() -> Self {
        Self {
            overrides: HashMap::new(),
        }
    }

    /// Sets an override for a specific flag.
    ///
    /// # Arguments
    ///
    /// * `flag` - The flag to override
    /// * `state` - The desired state (Enabled or Disabled)
    pub(super) fn set(&mut self, flag: T, state: FlagState) {
        self.overrides.insert(flag, state);
    }

    /// Enables a specific flag by setting its override state to Enabled.
    ///
    /// This is a convenience method equivalent to `set(flag, FlagState::Enabled)`.
    ///
    /// # Arguments
    ///
    /// * `flag` - The flag to enable
    ///
    /// # Examples
    ///
    /// ```rust
    /// use pvimg::uvdata::{FlagsOverride, SeHdrFlag};
    ///
    /// let mut overrides = FlagsOverride::new();
    /// overrides.enable(SeHdrFlag::ConfidentialDump);
    /// ```
    pub fn enable(&mut self, flag: T) {
        self.set(flag, FlagState::Enabled);
    }

    /// Disables a specific flag by setting its override state to Disabled.
    ///
    /// This is a convenience method equivalent to `set(flag, FlagState::Disabled)`.
    ///
    /// # Arguments
    ///
    /// * `flag` - The flag to disable
    ///
    /// # Examples
    ///
    /// ```rust
    /// use pvimg::uvdata::{FlagsOverride, SeHdrFlag};
    ///
    /// let mut overrides = FlagsOverride::new();
    /// overrides.disable(SeHdrFlag::PckmoAes);
    /// ```
    pub fn disable(&mut self, flag: T) {
        self.set(flag, FlagState::Disabled);
    }

    /// Enables multiple flags at once from an iterator.
    ///
    /// This is a convenience method for enabling multiple flags in a single call.
    ///
    /// # Arguments
    ///
    /// * `flags` - An iterator over flags to enable
    ///
    /// # Examples
    ///
    /// ```rust
    /// use pvimg::uvdata::{FlagsOverride, SeHdrFlag};
    ///
    /// let mut overrides = FlagsOverride::new();
    /// overrides.enable_all([SeHdrFlag::ConfidentialDump, SeHdrFlag::PckmoAes]);
    /// ```
    pub fn enable_all<I>(&mut self, flags: I)
    where
        I: IntoIterator<Item = T>,
    {
        for flag in flags {
            self.enable(flag);
        }
    }

    /// Disables multiple flags at once from an iterator.
    ///
    /// This is a convenience method for disabling multiple flags in a single call.
    ///
    /// # Arguments
    ///
    /// * `flags` - An iterator over flags to disable
    ///
    /// # Examples
    ///
    /// ```rust
    /// use pvimg::uvdata::{FlagsOverride, SeHdrFlag};
    ///
    /// let mut overrides = FlagsOverride::new();
    /// overrides.disable_all([SeHdrFlag::PckmoAes, SeHdrFlag::PckmoEcc]);
    /// ```
    pub fn disable_all<I>(&mut self, flags: I)
    where
        I: IntoIterator<Item = T>,
    {
        for flag in flags {
            self.disable(flag);
        }
    }

    /// Removes an override for a specific flag.
    ///
    /// # Arguments
    ///
    /// * `flag` - The flag to remove the override for
    ///
    /// # Returns
    ///
    /// The previous state if it existed, None otherwise
    pub fn remove(&mut self, flag: T) -> Option<FlagState> {
        self.overrides.remove(&flag)
    }

    /// Gets the override state for a specific flag.
    ///
    /// # Arguments
    ///
    /// * `flag` - The flag to query
    ///
    /// # Returns
    ///
    /// The override state if it exists, None otherwise
    pub fn get(&self, flag: T) -> Option<FlagState> {
        self.overrides.get(&flag).copied()
    }

    /// Checks if an override exists for a specific flag.
    ///
    /// # Arguments
    ///
    /// * `flag` - The flag to check
    pub fn has_override(&self, flag: T) -> bool {
        self.overrides.contains_key(&flag)
    }

    /// Returns an iterator over all overrides.
    pub fn iter(&self) -> impl Iterator<Item = (&T, &FlagState)> {
        self.overrides.iter()
    }

    /// Returns an iterator over all flags that have overrides.
    pub fn flags(&self) -> impl Iterator<Item = &T> {
        self.overrides.keys()
    }

    /// Returns the number of overrides.
    pub fn len(&self) -> usize {
        self.overrides.len()
    }

    /// Checks if there are no overrides.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.overrides.is_empty()
    }

    /// Clears all overrides.
    pub fn clear(&mut self) {
        self.overrides.clear();
    }
}

impl<T: ControlFlagTrait> Default for FlagsOverride<T> {
    fn default() -> Self {
        Self::new()
    }
}
