use std::{
    convert::TryFrom,
    fmt::{self, Debug, Display, Formatter},
};

use super::*;

// https://datatracker.ietf.org/doc/html/draft-sharabayko-srt-00#section-6
// https://github.com/Haivision/srt/blob/master/docs/features/encryption.md
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct Encryption {
    // TODO: support unspecified key length
    //  also check to ensure we implement key negotiation algorithm correctly
    /// SRTO_PBKEYLEN
    ///
    /// Encryption key length.
    ///
    /// Possible values:
    ///
    ///  0  = PBKEYLEN (default value)
    ///  16 = AES-128 (effective value)
    ///  24 = AES-192
    ///  32 = AES-256
    ///
    /// The use is slightly different in 1.2.0 (HSv4), and since 1.3.0 (HSv5):
    ///
    /// HSv4: This is set on the sender and enables encryption, if not 0. The receiver shall not set
    /// it and will agree on the length as defined by the sender.
    ///
    /// HSv5: The "default value" for PBKEYLEN is 0, which means that the PBKEYLEN won't be
    /// advertised. The "effective value" for PBKEYLEN is 16, but this applies only when neither
    /// party has set the value explicitly (i.e. when both are initially at the default value of 0).
    /// If any party has set an explicit value (16, 24, 32) it will be advertised in the handshake.
    /// If the other party remains at the default 0, it will accept the peer's value. The situation
    /// where both parties set a value should be treated carefully. Actually there are three
    /// intended methods of defining it, and all other uses are considered undefined behavior:
    ///
    /// Unidirectional: the sender shall set PBKEYLEN and the receiver shall not alter the default
    /// value 0. The effective PBKEYLEN will be the one set on the sender. The receiver need not
    /// know the sender's PBKEYLEN, just the passphrase, PBKEYLEN will be correctly passed.
    ///
    /// Bidirectional in Caller-Listener arrangement: it is recommended to use a rule whereby you
    /// will be setting the PBKEYLEN exclusively either on the Listener or on the Caller. The value
    /// set on the Listener will win, if set on both parties.
    ///
    /// Bidirectional in Rendezvous arrangement: you have to know the passphrases for both parties,
    /// as well as PBKEYLEN. Set PBKEYLEN to the same value on both parties (or leave the default
    /// value on both parties, which will result in 16)
    ///
    /// Unwanted behavior cases: if both parties set PBKEYLEN and the value on both sides is
    /// different, the effective PBKEYLEN will be the one that is set on the Responder party, which
    /// may also override the PBKEYLEN 32 set by the sender to value 16 if such value was used by
    /// the receiver. The Responder party is the Listener in a Caller-Listener arrangement. In
    /// Rendezvous it's a matter of luck which party becomes the Responder.
    pub key_size: KeySize,

    /// SRTO_PASSPHRASE
    /// Sets the passphrase for encryption. This enables encryption on this party (or disables it, if
    /// an empty passphrase is passed). The password must be minimum 10 and maximum 79 characters
    /// long.
    ///
    /// The passphrase is the shared secret between the sender and the receiver. It is used to
    /// generate the Key Encrypting Key using PBKDF2 (Password-Based Key Derivation Function 2).
    ///
    /// When a socket with configured passphrase is being connected, the peer must have the same
    /// password set, or the connection is rejected. This behavior can be changed by
    /// SRTO_ENFORCEDENCRYPTION.
    ///
    /// Note that since the introduction of bidirectional support, there's only one initial
    /// encryption key to encrypt the stream (new keys after refreshing will be updated
    /// independently), and there's no distinction between "service party that defines the password"
    /// and "client party that is required to set matching password" - both parties are equivalent,
    /// and in order to have a working encrypted connection, they have to simply set the same
    /// passphrase.
    pub passphrase: Option<Passphrase>,

    pub km_refresh: KeyMaterialRefresh,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyMaterialRefresh {
    /// SRTO_KMREFRESHRATE
    /// KM Refresh Period specifies the number of packets to be sent
    /// before switching to the new SEK
    ///
    /// The recommended KM Refresh Period is after 2^25 packets encrypted
    /// with the same SEK are sent.
    ///
    /// The number of packets to be transmitted after which the Stream Encryption Key (SEK), used to
    /// encrypt packets, will be switched to the new one. Note that the old and new keys live in
    /// parallel for a certain period of time (see SRTO_KMPREANNOUNCE) before and after the
    /// switchover.
    ///
    /// Having a preannounce period before switchover ensures the new SEK is installed at the
    /// receiver before the first packet encrypted with the new SEK is received. The old key remains
    /// active after switchover in order to decrypt packets that might still be in flight, or
    /// packets that have to be retransmitted.
    ///
    /// Default value: 0 - corresponds to 16777216 packets (2^24 or 0x1000000).
    pub period: PacketCount,

    /// SRTO_KMPREANNOUNCE
    /// KM Pre-Announcement Period specifies when a new key is announced
    /// in a number of packets before key switchover.  The same value is
    /// used to determine when to decommission the old key after
    /// switchover.
    ///
    /// The recommended KM Pre-Announcement Period is 4000 packets (i.e.
    /// a new key is generated, wrapped, and sent at 2^25 minus 4000
    /// packets; the old key is decommissioned at 2^25 plus 4000
    /// packets).
    ///
    /// The interval (defined in packets) between when a new Stream Encrypting Key (SEK) is sent and
    /// when switchover occurs. This value also applies to the subsequent interval between when
    /// switchover occurs and when the old SEK is decommissioned.
    ///
    /// At SRTO_KMPREANNOUNCE packets before switchover the new key is sent (repeatedly, if
    /// necessary, until it is confirmed by the receiver).
    ///
    /// At the switchover point (see SRTO_KMREFRESHRATE), the sender starts encrypting and sending
    /// packets using the new key. The old key persists in case it is needed to decrypt packets that
    /// were in the flight window, or retransmitted packets.
    ///
    /// The old key is decommissioned at SRTO_KMPREANNOUNCE packets after switchover.
    ///
    /// The allowed range for this value is between 1 and half of the current value of
    /// SRTO_KMREFRESHRATE. The minimum value should never be less than the flight window SRTO_FC
    /// (i.e. the number of packets that have already left the sender but have not yet arrived at
    /// the receiver).
    ///
    /// The value of SRTO_KMPREANNOUNCE must not exceed (SRTO_KMREFRESHRATE - 1) / 2`.
    ///
    /// Default value: 2^12
    pub pre_announcement_period: PacketCount,
}

impl Default for KeyMaterialRefresh {
    fn default() -> Self {
        Self {
            period: PacketCount(1u64 << 24),                  // 2^25
            pre_announcement_period: PacketCount(1u64 << 12), // 2^12,
        }
    }
}

impl Validation for Encryption {
    type Error = OptionsError;

    fn is_valid(&self) -> Result<(), Self::Error> {
        let period: u64 = self.km_refresh.period.into();
        let pre_announcement_period: u64 = self.km_refresh.pre_announcement_period.into();

        if period == 0 || pre_announcement_period > period.saturating_sub(1) / 2 {
            Err(OptionsError::KeyMaterialRefresh(
                PacketCount(period),
                PacketCount(pre_announcement_period),
            ))
        } else {
            Ok(())
        }
    }
}

// https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md#srto_passphrase
#[derive(Clone, Eq, PartialEq)]
pub struct Passphrase(String);

impl<'a> From<&'a str> for Passphrase {
    fn from(value: &'a str) -> Self {
        Self::try_from(value.to_string()).unwrap()
    }
}

impl TryFrom<String> for Passphrase {
    type Error = OptionsError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if !(10..=79).contains(&value.len()) {
            return Err(OptionsError::PassphraseLength(value.len()));
        }
        Ok(Passphrase(value))
    }
}

impl Passphrase {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Display for Passphrase {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

impl Debug for Passphrase {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Passphrase").finish()
    }
}

// https://github.com/Haivision/srt/blob/master/docs/API/API-socket-options.md#srto_pbkeylen
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub enum KeySize {
    #[default]
    Unspecified,
    AES128,
    AES192,
    AES256,
}

impl KeySize {
    pub fn as_raw(self) -> u8 {
        use KeySize::*;
        match self {
            Unspecified => 0,
            AES128 => 16,
            AES192 => 24,
            AES256 => 32,
        }
    }

    pub fn as_usize(self) -> usize {
        use KeySize::*;
        match self {
            Unspecified => 16,
            AES128 => 16,
            AES192 => 24,
            AES256 => 32,
        }
    }
}

impl TryFrom<u8> for KeySize {
    type Error = OptionsError;

    fn try_from(value: u8) -> Result<Self, OptionsError> {
        use KeySize::*;
        match value {
            0 => Ok(Unspecified),
            16 => Ok(AES128),
            24 => Ok(AES192),
            32 => Ok(AES256),
            value => Err(OptionsError::InvalidKeySize(value)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatting() {
        assert_eq!(
            format!("{:?}", Passphrase::from("1234567890")),
            "Passphrase"
        );
    }

    #[test]
    fn try_from() {
        use OptionsError::*;
        assert_eq!(
            Passphrase::try_from("123456789".to_string()),
            Err(PassphraseLength(9))
        );
        assert_eq!(
            Passphrase::try_from(String::from_utf8_lossy(&[b'X'; 80]).to_string()),
            Err(PassphraseLength(80))
        );
    }
}
