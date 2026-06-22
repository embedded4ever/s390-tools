// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.

//! Helper traits and utilities for testing the ControlFlag derive macro.

/// Trait for control flags that provide bit position information.
pub trait ControlFlagTrait {
    /// Returns the bit position for this flag.
    fn bit_position(self) -> u8;
}

/// Trait for enums that can be iterated over.
pub trait IntoEnumIterator: Sized {
    /// Returns an iterator over all variants of the enum.
    fn iter() -> impl Iterator<Item = Self>;
}
