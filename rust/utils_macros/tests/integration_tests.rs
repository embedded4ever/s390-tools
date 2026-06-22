// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.

//! Integration tests for the ControlFlag derive macro.

mod test_helpers;

use test_helpers::{ControlFlagTrait, IntoEnumIterator};
use utils_macros::ControlFlag;

// Test enum for basic functionality
#[derive(ControlFlag, Debug, Clone, Copy, PartialEq, Eq)]
enum TestFlag {
    #[flag(display = "first flag", value = 1)]
    First,
    #[flag(display = "second flag", value = 2)]
    Second,
}

// Test enum with multiple variants
#[derive(ControlFlag, Debug, Clone, Copy, PartialEq, Eq)]
enum MultiFlag {
    #[flag(display = "flag 1", value = 10)]
    Flag1,
    #[flag(display = "flag 2", value = 20)]
    Flag2,
    #[flag(display = "flag 3", value = 30)]
    Flag3,
    #[flag(display = "flag 4", value = 40)]
    Flag4,
    #[flag(display = "flag 5", value = 50)]
    Flag5,
}

// Test enum with non-sequential values
#[derive(ControlFlag, Debug, Clone, Copy, PartialEq, Eq)]
enum SparseFlag {
    #[flag(display = "low bit", value = 1)]
    Low,
    #[flag(display = "high bit", value = 63)]
    High,
    #[flag(display = "middle bit", value = 32)]
    Middle,
}

// Test enum with edge case display strings
#[derive(ControlFlag, Debug, Clone, Copy, PartialEq, Eq)]
enum EdgeCaseFlag {
    #[flag(display = "simple", value = 1)]
    Simple,
    #[flag(display = "with spaces and punctuation!", value = 2)]
    WithSpaces,
    #[flag(display = "UPPERCASE", value = 3)]
    Uppercase,
    #[flag(display = "with-dashes-and_underscores", value = 4)]
    WithDashes,
}

// Test enum for Copy/Clone compatibility
#[derive(ControlFlag, Copy, Clone, Debug, PartialEq, Eq)]
enum CopyableFlag {
    #[flag(display = "copyable", value = 1)]
    Copyable,
    #[flag(display = "another", value = 2)]
    Another,
}

#[test]
fn test_basic_derive() {
    // Verify the macro successfully derives all required traits
    let flag = TestFlag::First;

    // Should compile and be accessible
    let _ = flag.flag_value();
    let _ = flag.bit_position();
    let _ = format!("{}", flag);
    let _ = TestFlag::iter();
}

#[test]
fn test_display_trait() {
    // Verify custom display strings are correctly used
    assert_eq!(format!("{}", TestFlag::First), "first flag");
    assert_eq!(format!("{}", TestFlag::Second), "second flag");
}

#[test]
fn test_enum_iterator() {
    // Verify iteration over all enum variants works correctly
    let flags: Vec<TestFlag> = TestFlag::iter().collect();
    assert_eq!(flags.len(), 2);
    assert_eq!(flags[0], TestFlag::First);
    assert_eq!(flags[1], TestFlag::Second);
}

#[test]
fn test_control_flag_trait() {
    // Verify bit_position() returns correct values
    assert_eq!(TestFlag::First.bit_position(), 1);
    assert_eq!(TestFlag::Second.bit_position(), 2);
}

#[test]
fn test_flag_value_method() {
    // Verify flag_value() returns correct bit positions
    assert_eq!(TestFlag::First.flag_value(), 1);
    assert_eq!(TestFlag::Second.flag_value(), 2);
}

#[test]
fn test_multiple_variants() {
    // Verify the macro handles enums with many variants

    // Test iteration
    let flags: Vec<MultiFlag> = MultiFlag::iter().collect();
    assert_eq!(flags.len(), 5);
    assert_eq!(flags[0], MultiFlag::Flag1);
    assert_eq!(flags[1], MultiFlag::Flag2);
    assert_eq!(flags[2], MultiFlag::Flag3);
    assert_eq!(flags[3], MultiFlag::Flag4);
    assert_eq!(flags[4], MultiFlag::Flag5);

    // Test bit positions
    assert_eq!(MultiFlag::Flag1.bit_position(), 10);
    assert_eq!(MultiFlag::Flag2.bit_position(), 20);
    assert_eq!(MultiFlag::Flag3.bit_position(), 30);
    assert_eq!(MultiFlag::Flag4.bit_position(), 40);
    assert_eq!(MultiFlag::Flag5.bit_position(), 50);

    // Test display strings
    assert_eq!(format!("{}", MultiFlag::Flag1), "flag 1");
    assert_eq!(format!("{}", MultiFlag::Flag2), "flag 2");
    assert_eq!(format!("{}", MultiFlag::Flag3), "flag 3");
    assert_eq!(format!("{}", MultiFlag::Flag4), "flag 4");
    assert_eq!(format!("{}", MultiFlag::Flag5), "flag 5");
}

#[test]
fn test_non_sequential_values() {
    // Verify the macro handles non-sequential bit position values
    assert_eq!(SparseFlag::Low.bit_position(), 1);
    assert_eq!(SparseFlag::High.bit_position(), 63);
    assert_eq!(SparseFlag::Middle.bit_position(), 32);

    // Verify iteration order matches declaration order
    let flags: Vec<SparseFlag> = SparseFlag::iter().collect();
    assert_eq!(flags.len(), 3);
    assert_eq!(flags[0], SparseFlag::Low);
    assert_eq!(flags[1], SparseFlag::High);
    assert_eq!(flags[2], SparseFlag::Middle);
}

#[test]
fn test_display_string_edge_cases() {
    // Verify various display string formats work correctly
    assert_eq!(format!("{}", EdgeCaseFlag::Simple), "simple");
    assert_eq!(
        format!("{}", EdgeCaseFlag::WithSpaces),
        "with spaces and punctuation!"
    );
    assert_eq!(format!("{}", EdgeCaseFlag::Uppercase), "UPPERCASE");
    assert_eq!(
        format!("{}", EdgeCaseFlag::WithDashes),
        "with-dashes-and_underscores"
    );
}

#[test]
fn test_trait_bounds() {
    // Verify generated implementations work with common trait bounds

    // Function that requires Display
    fn requires_display<T: std::fmt::Display>(flag: T) -> String {
        format!("{}", flag)
    }

    // Function that requires IntoEnumIterator
    fn requires_iterator<T: IntoEnumIterator>() -> Vec<T> {
        T::iter().collect()
    }

    // Test with TestFlag
    let result = requires_display(TestFlag::First);
    assert_eq!(result, "first flag");

    let flags: Vec<TestFlag> = requires_iterator();
    assert_eq!(flags.len(), 2);
}

#[test]
fn test_copy_clone_compatibility() {
    // Verify the macro works with Copy and Clone derives
    let flag1 = CopyableFlag::Copyable;
    let flag2 = flag1; // Copy
    let flag3 = flag1; // Clone

    assert_eq!(flag1, flag2);
    assert_eq!(flag1, flag3);

    // Verify all methods still work
    assert_eq!(flag1.bit_position(), 1);
    assert_eq!(flag2.flag_value(), 1);
    assert_eq!(format!("{}", flag3), "copyable");
}

#[test]
fn test_iterator_multiple_calls() {
    // Verify iterator can be called multiple times
    let iter1: Vec<TestFlag> = TestFlag::iter().collect();
    let iter2: Vec<TestFlag> = TestFlag::iter().collect();

    assert_eq!(iter1, iter2);
    assert_eq!(iter1.len(), 2);
}

#[test]
fn test_flag_value_const() {
    // Verify flag_value() can be used in const contexts
    const FLAG_VALUE: u8 = TestFlag::First.flag_value();
    assert_eq!(FLAG_VALUE, 1);
}

#[test]
fn test_all_variants_unique_values() {
    // Verify all variants have unique bit positions
    let flags: Vec<TestFlag> = TestFlag::iter().collect();
    let values: Vec<u8> = flags.iter().map(|f| f.bit_position()).collect();

    // Check uniqueness
    for i in 0..values.len() {
        for j in (i + 1)..values.len() {
            assert_ne!(values[i], values[j], "Duplicate bit position found");
        }
    }
}

#[test]
fn test_display_consistency() {
    // Verify Display is consistent across multiple calls
    let flag = TestFlag::First;
    let display1 = format!("{}", flag);
    let display2 = format!("{}", flag);

    assert_eq!(display1, display2);
    assert_eq!(display1, "first flag");
}
