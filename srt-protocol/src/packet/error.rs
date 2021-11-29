use std::{error::Error, fmt, io, str::Utf8Error};

#[derive(Debug)]
#[non_exhaustive]
pub enum PacketParseError {
    NotEnoughData,
    BadUdtVersion(i32),
    BadConnectionType(i32),
    BadSocketType(u16),
    BadControlType(u16),
    UnsupportedSrtExtensionType(u16),
    BadSrtExtensionMessage, // could be split
    BadCryptoLength(u32),
    BadCipherKind(u8),
    BadKeyPacketType(u8),
    BadKeySign(u16),
    BadAuth(u8),
    BadStreamEncapsulation(u8),
    StreamEncapsulationNotSrt,
    BadDataEncryption(u8),
    StreamTypeNotUtf8(Utf8Error),
    ZeroAckSequenceNumber,
    BadFilter(String),
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

impl From<io::Error> for PacketParseError {
    fn from(s: io::Error) -> PacketParseError {
        PacketParseError::Io(s)
    }
}

// NOTE: can't derive Eq or PartialEq because io::Error does not implement either.
impl Eq for PacketParseError {}

impl PartialEq for PacketParseError {
    fn eq(&self, other: &Self) -> bool {
        use PacketParseError::*;
        match (self, other) {
            (BadSrtExtensionMessage, BadSrtExtensionMessage)
            | (StreamEncapsulationNotSrt, StreamEncapsulationNotSrt)
            | (ZeroAckSequenceNumber, ZeroAckSequenceNumber) => true,

            (BadUdtVersion(s), BadUdtVersion(o)) | (BadConnectionType(s), BadConnectionType(o)) => {
                s == o
            }

            (BadSocketType(s), BadSocketType(o))
            | (BadControlType(s), BadControlType(o))
            | (UnsupportedSrtExtensionType(s), UnsupportedSrtExtensionType(o))
            | (BadKeySign(s), BadKeySign(o)) => s == o,

            (BadCipherKind(s), BadCipherKind(o))
            | (BadKeyPacketType(s), BadKeyPacketType(o))
            | (BadAuth(s), BadAuth(o))
            | (BadStreamEncapsulation(s), BadStreamEncapsulation(o))
            | (BadDataEncryption(s), BadDataEncryption(o)) => s == o,

            (StreamTypeNotUtf8(s), StreamTypeNotUtf8(o)) => s == o,
            (BadFilter(s), BadFilter(o)) => s == o,

            (Io(s), Io(o)) => s.kind() == o.kind() && s.raw_os_error() == o.raw_os_error(),
            _ => false,
        }
    }
}
