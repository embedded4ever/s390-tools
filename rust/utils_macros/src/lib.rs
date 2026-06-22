// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp.

//! Procedural macros for the utils crate.
//!
//! This crate provides derive macros to reduce boilerplate in enum definitions,
//! particularly for control flags.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Lit, Meta, MetaList};

/// Derive macro for control flag enums.
///
/// This macro generates implementations for `Display`, `IntoEnumIterator`, and `ControlFlagTrait`.
/// It supports the `#[flag(display = "...", value = N)]` attribute to specify custom display
/// strings and discriminant values.
///
/// # Example
///
/// ```
/// use utils_macros::ControlFlag;
///
/// /// Trait for enums that can be iterated over.
/// pub trait IntoEnumIterator: Sized {
///     /// Returns an iterator over all variants of the enum.
///     fn iter() -> impl Iterator<Item = Self>;
/// }
///
/// /// Trait for control flags that provide bit position information.
/// pub trait ControlFlagTrait {
///     /// Returns the bit position for this flag.
///     fn bit_position(self) -> u8;
/// }
///
/// #[derive(ControlFlag)]
/// pub enum PcfV1 {
///     #[flag(display = "Confidential dump support", value = 34)]
///     ConfidentialDump,
///
///     #[flag(display = "V1-specific flag", value = 35)]
///     V1OnlyFlag,
/// }
/// ```
#[proc_macro_derive(ControlFlag, attributes(flag))]
pub fn derive_control_flag(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let variants = match &input.data {
        Data::Enum(data) => &data.variants,
        _ => panic!("ControlFlag can only be derived for enums"),
    };

    // Extract variant information
    let mut variant_names = Vec::new();
    let mut variant_displays = Vec::new();
    let mut variant_values = Vec::new();

    for variant in variants {
        if !matches!(variant.fields, Fields::Unit) {
            panic!("ControlFlag only supports unit variants");
        }

        let variant_name = &variant.ident;
        variant_names.push(variant_name);

        // Parse the #[flag(...)] attribute
        let mut display_str = variant_name.to_string();
        let mut value: Option<u8> = None;

        for attr in &variant.attrs {
            if attr.path().is_ident("flag") {
                // Try to parse as MetaList
                if let Meta::List(MetaList { tokens, .. }) = &attr.meta {
                    // Parse the tokens inside the list
                    let parser = syn::meta::parser(|meta| {
                        if meta.path.is_ident("display") {
                            let val = meta.value()?;
                            let lit: Lit = val.parse()?;
                            if let Lit::Str(s) = lit {
                                display_str = s.value();
                            }
                        } else if meta.path.is_ident("value") {
                            let val = meta.value()?;
                            let lit: Lit = val.parse()?;
                            if let Lit::Int(i) = lit {
                                value = Some(i.base10_parse()?);
                            }
                        }
                        Ok(())
                    });

                    let _ = syn::parse::Parser::parse2(parser, tokens.clone());
                }
            }
        }

        if value.is_none() {
            panic!(
                "ControlFlag variant {} must have a value attribute",
                variant_name
            );
        }

        variant_displays.push(display_str);
        variant_values.push(value.unwrap());
    }

    let expanded = quote! {
        impl #name {
            /// Returns the bit position value for this flag.
            pub const fn flag_value(&self) -> u8 {
                match self {
                    #(Self::#variant_names => #variant_values),*
                }
            }
        }

        impl ControlFlagTrait for #name {
            fn bit_position(self) -> u8 {
                self.flag_value()
            }
        }

        impl std::fmt::Display for #name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "{}",
                    match self {
                        #(Self::#variant_names => #variant_displays),*
                    }
                )
            }
        }

        impl IntoEnumIterator for #name {
            fn iter() -> impl Iterator<Item = Self> {
                [
                    #(Self::#variant_names),*
                ]
                .into_iter()
            }
        }
    };

    TokenStream::from(expanded)
}

/// Derive `std::fmt::Display` for enums implementing `clap::ValueEnum`.
///
/// This macro generates a `Display` implementation that delegates to
/// `ValueEnum::to_possible_value()`, ensuring that the formatted output
/// matches the CLI representation used by clap (e.g. for help text,
/// completions, and parsing).
///
/// # Behavior
///
/// - Uses the canonical CLI name of each variant (as defined by `#[value(name = "...")]` or the
///   default casing).
/// - Fails at runtime if a variant is marked with `#[value(skip)]` and therefore has no CLI
///   representation.
///
/// # Example
///
/// ```rust
/// use clap::ValueEnum;
/// use utils_macros::ValueEnumDisplay;
///
/// #[derive(ValueEnum, ValueEnumDisplay, Clone)]
/// enum Mode {
///     #[value(name = "very-fast")]
///     Fast,
///
///     #[value(name = "slow")]
///     Slow,
/// }
///
/// assert_eq!(Mode::Fast.to_string(), "very-fast");
/// ```
///
/// # Rationale
///
/// clap requires `Display` for features like `default_value_t`. However,
/// `ValueEnum` already defines the canonical string representation via
/// `to_possible_value()`. This derive avoids duplicating those strings
/// and guarantees consistency between parsing, help output, and display.
///
/// # Panics
///
/// Panics if called on a variant with `#[value(skip)]`, as such variants
/// have no associated CLI representation.
///
/// # See also
///
/// - [`clap::ValueEnum`]
/// - [`clap::builder::PossibleValue`]
#[proc_macro_derive(ValueEnumDisplay)]
pub fn derive_value_enum_display(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let expanded = quote! {
        impl std::fmt::Display for #name {
            fn fmt(
                &self,
                f: &mut std::fmt::Formatter<'_>,
            ) -> std::fmt::Result {
                let value = self
                    .to_possible_value()
                    .expect("skipped ValueEnum variant cannot be displayed");

                write!(f, "{}", value.get_name())
            }
        }
    };

    expanded.into()
}

/// Derives a `std::str::FromStr` implementation for enums implementing
/// [`clap::ValueEnum`].
///
/// This macro generates a `FromStr` implementation that delegates to
/// [`ValueEnum::from_str`], ensuring that parsing behavior is identical
/// to clap's CLI parsing.
///
/// # Behavior
///
/// - Parses input strings using the canonical CLI representation defined by `ValueEnum` (including
///   `#[value(name = "...")]` and aliases).
/// - Supports the same parsing semantics as clap (e.g. case sensitivity, if enabled).
/// - Returns a human-readable error if parsing fails.
///
/// # Example
///
/// ```rust
/// use clap::ValueEnum;
/// use utils_macros::ValueEnumFromStr;
///
/// #[derive(ValueEnum, ValueEnumFromStr, Clone, Debug, PartialEq)]
/// enum Mode {
///     #[value(name = "fast")]
///     Fast,
///
///     #[value(name = "slow")]
///     Slow,
/// }
///
/// assert_eq!("fast".parse::<Mode>().unwrap(), Mode::Fast);
/// assert!("invalid".parse::<Mode>().is_err());
/// ```
///
/// # Rationale
///
/// clap's [`ValueEnum`] trait already defines the canonical mapping
/// between strings and enum variants. This derive avoids duplicating
/// that logic in manual `FromStr` implementations and guarantees that
/// CLI parsing and programmatic parsing remain consistent.
///
/// # Errors
///
/// Returns an error if the input does not match any of the allowed values
/// defined by `ValueEnum`.
///
/// # See also
///
/// - [`clap::ValueEnum`]
/// - [`std::str::FromStr`]
#[proc_macro_derive(ValueEnumFromStr)]
pub fn derive_value_enum_from_str(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let expanded = quote! {
        impl std::str::FromStr for #name {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                <Self as clap::ValueEnum>::from_str(s, false).map_err(|_| {
                    let possible = <Self as clap::ValueEnum>::value_variants()
                        .iter()
                        .filter_map(|v| v.to_possible_value())
                        .map(|v| v.get_name().to_string())
                        .collect::<Vec<_>>()
                        .join(", ");

                    format!("invalid value '{}', expected one of: {}", s, possible)
                })
            }
        }
    };

    expanded.into()
}
