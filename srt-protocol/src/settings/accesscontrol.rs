use std::convert::TryInto;

use crate::{options::OptionsError, settings::KeySettings};

#[derive(Debug, Eq, PartialEq)]
pub struct AcceptParameters {
    key_settings: Option<KeySettings>,
}

impl AcceptParameters {
    pub fn new() -> AcceptParameters {
        AcceptParameters { key_settings: None }
    }

    pub fn set_key_settings(
        &mut self,
        passphrase: impl Into<String>,
        size: u8,
    ) -> Result<&mut Self, OptionsError> {
        self.key_settings = Some(KeySettings {
            key_size: size.try_into()?,
            passphrase: passphrase.into().try_into()?,
        });
        Ok(self)
    }

    pub fn take_key_settings(&mut self) -> Option<KeySettings> {
        self.key_settings.take()
    }
}

impl Default for AcceptParameters {
    fn default() -> Self {
        AcceptParameters::new()
    }
}
