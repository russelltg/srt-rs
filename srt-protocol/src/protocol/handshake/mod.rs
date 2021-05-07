use crate::packet::{ControlTypes, HandshakeControlInfo, ShakeType};

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Handshake {
    Connector,
    Listener(ControlTypes),
    Rendezvous(Option<ControlTypes>),
}

impl Handshake {
    pub fn handle_handshake(&self, handshake: &HandshakeControlInfo) -> Option<ControlTypes> {
        match (self, handshake.shake_type) {
            (Handshake::Rendezvous(control), ShakeType::Conclusion) => control.clone(),
            (Handshake::Listener(control), _) => Some(control.clone()),
            (Handshake::Connector, _) | (Handshake::Rendezvous(_), _) => None,
        }
    }
}
