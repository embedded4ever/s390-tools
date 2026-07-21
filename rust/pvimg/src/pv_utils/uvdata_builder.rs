// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

use std::fmt::Display;

use enum_dispatch::enum_dispatch;
use openssl::pkey::{PKey, Private};
use pv::request::{Confidential, SymKey};

use super::Error;
use crate::pv_utils::error::Result;
use crate::pv_utils::uvdata::{AeadCipherTrait, UvDataPlainTrait};

#[enum_dispatch]
pub trait AeadCipherBuilderTrait: AeadCipherTrait {
    fn set_iv(&mut self, iv: &[u8]) -> Result<()>;
    fn generate_aead_key(&self) -> Result<SymKey> {
        Ok(SymKey::random(self.aead_key_type())?)
    }
}

/// Key exchange related methods
pub trait KeyExchangeBuilderTrait {
    type TargetKeyType: ToOwned;
    type AeadKeyType: Display + std::fmt::Debug;
    type PrivateKeyType: ToOwned;

    fn add_keyslot(
        &mut self,
        hostkey: &Self::TargetKeyType,
        aead_key: &Self::AeadKeyType,
        priv_key: &Self::PrivateKeyType,
    ) -> Result<()>;

    fn clear_keyslots(&mut self) -> Result<()>;
    // TODO How to handle PKey vs &PKeyRef?
    fn generate_private_key(&self) -> Result<PKey<Private>>;
    fn set_cust_public_key(&mut self, key: &Self::PrivateKeyType) -> Result<()>;
}

pub struct UvDataBuilder<T: KeyExchangeBuilderTrait + AeadCipherBuilderTrait> {
    pub(crate) expert_mode: bool,
    pub(crate) prot_key: T::AeadKeyType,
    pub(crate) priv_key: T::PrivateKeyType,
    pub(crate) target_keys: Vec<T::TargetKeyType>,
    pub(crate) plain_data: T,
}

impl<T: KeyExchangeBuilderTrait + AeadCipherBuilderTrait> UvDataBuilder<T> {
    /// Enable expert mode - this is required for specifying PSW, etc.
    pub fn i_know_what_i_am_doing(&mut self) {
        self.expert_mode = true;
    }
}

impl<T: std::fmt::Debug + KeyExchangeBuilderTrait + AeadCipherBuilderTrait + UvDataPlainTrait>
    std::fmt::Debug for UvDataBuilder<T>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UvDataBuilder")
            .field("expert_mode", &self.expert_mode)
            .field("prot_key", &self.prot_key)
            .field("plain_data", &self.plain_data)
            .finish()
    }
}

impl<T> UvDataBuilder<T>
where
    T: KeyExchangeBuilderTrait<AeadKeyType = SymKey> + AeadCipherBuilderTrait,
{
    pub fn add_hostkeys(&mut self, hostkeys: &[T::TargetKeyType]) -> Result<&mut Self>
    where
        T::TargetKeyType: Clone,
    {
        for hk in hostkeys {
            self.plain_data
                .add_keyslot(hk, &self.prot_key, &self.priv_key)?;
            self.target_keys.push(hk.clone());
        }

        Ok(self)
    }

    pub fn with_iv(&mut self, iv: &[u8]) -> Result<&mut Self> {
        if !self.expert_mode {
            return Err(Error::NonExpertMode);
        }
        self.plain_data.set_iv(iv)?;
        Ok(self)
    }

    fn update_target_key_slots(&mut self) -> Result<()> {
        self.plain_data.clear_keyslots()?;
        for hostkey in &self.target_keys {
            self.plain_data
                .add_keyslot(hostkey, &self.prot_key, &self.priv_key)?;
        }
        Ok(())
    }

    pub fn with_aead_key(&mut self, data: Confidential<Vec<u8>>) -> Result<&mut Self> {
        if !self.expert_mode {
            return Err(Error::NonExpertMode);
        }
        // TODO Implement TryFrom<...> ?!
        let key = SymKey::try_from_data(self.plain_data.aead_key_type(), data)?;
        self.prot_key = key;
        self.update_target_key_slots()?;

        Ok(self)
    }

    pub fn with_priv_key(&mut self, priv_key: &T::PrivateKeyType) -> Result<&mut Self>
    where
        T::PrivateKeyType: Clone,
    {
        if !self.expert_mode {
            return Err(Error::NonExpertMode);
        }
        self.plain_data.set_cust_public_key(priv_key)?;
        self.priv_key = priv_key.clone();
        self.update_target_key_slots()?;

        Ok(self)
    }

    pub const fn prot_key(&self) -> &<T as KeyExchangeBuilderTrait>::AeadKeyType {
        &self.prot_key
    }

    pub fn priv_key(&self) -> &<T as KeyExchangeBuilderTrait>::PrivateKeyType {
        &self.priv_key
    }
}

/// A trait for the builder pattern.
pub trait BuilderTrait {
    /// Data structure to construct
    type T;

    /// Builds the type [`Self::T`].
    ///
    /// # Errors
    ///
    /// This function will return an error if the data structure could not be
    /// build.
    fn build(self) -> Result<Self::T>;
}
