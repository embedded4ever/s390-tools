// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

mod error;
mod layout;
mod misc;
mod psw;
mod se_hdr;
mod secured_comp;
mod serializing;
mod uv_keys;
mod uvdata;
mod uvdata_builder;

pub use error::{Error, OwnExitCode, PvError, Result};
pub use layout::{Interval, Layout};
pub use misc::{round_up, try_copy_slice_to_array};
pub use psw::{ShortPsw, PSW, PSW_MASK_BA, PSW_MASK_EA};
pub use se_hdr::{
    ComponentMetadataV1, ControlFlagTrait, EffectiveControlFlags, EnvelopeSeHdrV1, FlagData,
    FlagState, FlagsOverride, IntoEnumIterator, SeH, SeHdr, SeHdrAadV1, SeHdrBinV1, SeHdrBuilder,
    SeHdrControlFlags, SeHdrControlFlagsModel, SeHdrData, SeHdrDataV1, SeHdrDataV2, SeHdrFlag,
    SeHdrPlain, SeHdrVersion, SeHdrVersioned, SeTarget, UnknownFlags,
};
pub use secured_comp::{ComponentTrait, SecuredComponent, SecuredComponentBuilder};
pub use serializing::{bytesize, serialize_to_bytes};
pub use uv_keys::UvKeyHashesV1;
pub use uvdata::{AeadPlainDataTrait, KeyExchangeTrait, UvDataPlainTrait, UvDataTrait};
pub use uvdata_builder::BuilderTrait;
