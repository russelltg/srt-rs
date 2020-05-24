use std::{error::Error, fmt, io};

#[derive(Debug)]
#[non_exhaustive]
pub enum PacketParseError {
    NotEnoughData,
    BadUDTVersion(i32),
    BadConnectionType(i32),
    BadSocketType(u16),
    BadControlType(u16),
    BadSRTHsExtensionType(u16),
    BadSRTKmExtensionType(u16),
    BadSRTConfigExtensionType(u16),
    BadSRTExtensionMessage, // could be split
    BadCryptoLength(u32),
    BadCipherKind(u8),
    BadKeyPacketType(u8),
    BadKeySign(u16),
    BadAuth(u8),
    BadStreamEncapsulation(u8),
    StreamEncapsulationNotSrt,
    BadDataEncryption(u8),
    Io(io::Error),
}

impl fmt::Display for PacketParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}
impl Error for PacketParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        if let PacketParseError::Io(e) = self {
            Some(e)
        } else {
            None
        }
    }
}

impl From<PacketParseError> for io::Error {
    fn from(s: PacketParseError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, s)
    }
}

impl From<io::Error> for PacketParseError {
    fn from(s: io::Error) -> PacketParseError {
        PacketParseError::Io(s)
    }
}
