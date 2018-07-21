/// The handshake responsibilty of a given SRT entity.
/// Defines roles in the sending/receiving of SRT control packets
///
/// This is decided based on who was the connector or listener during
/// connection initialization.
/// connector has `Request`, and listener has `Respond`.
///
/// In the case of rendezvous, the cookies are compared
/// and the side with the greater cookie gets `Request` responsibility,
/// and the smaller cookie gets `Respond` responsibility
#[derive(Copy, Clone, Debug)]
pub enum HandshakeResponsibility {
    Request,
    Respond,
}
