use std::{convert::TryInto, marker::PhantomData, net::SocketAddr};

use crate::{packet::RejectReason, settings::KeySettings};

pub struct AcceptParameters {
    key_settings: Option<KeySettings>,
}

impl AcceptParameters {
    pub fn new() -> AcceptParameters {
        AcceptParameters { key_settings: None }
    }

    pub fn set_key_settings(&mut self, passphrase: impl Into<String>, size: u16) -> &mut Self {
        self.key_settings = Some(KeySettings {
            key_size: size.try_into().unwrap(),
            passphrase: passphrase.into().try_into().unwrap(),
        });
        self
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

pub trait StreamAcceptor {
    fn accept(
        &mut self,
        streamid: Option<&str>,
        ip: SocketAddr,
    ) -> Result<AcceptParameters, RejectReason>;
}

#[derive(Default, Clone, Copy)]
pub struct AllowAllStreamAcceptor {
    _hidden: PhantomData<()>,
}

impl StreamAcceptor for AllowAllStreamAcceptor {
    fn accept(
        &mut self,
        _streamid: Option<&str>,
        _ip: SocketAddr,
    ) -> Result<AcceptParameters, RejectReason> {
        Ok(AcceptParameters::default())
    }
}
