use std::{cmp::Ordering, fmt};

/// Serialied, it looks like:
/// major * 0x10000 + minor * 0x100 + patch
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct SrtVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

impl SrtVersion {
    pub const CURRENT: SrtVersion = SrtVersion {
        major: 1,
        minor: 3,
        patch: 1,
    };

    /// Create a new SRT version
    pub fn new(major: u8, minor: u8, patch: u8) -> SrtVersion {
        SrtVersion {
            major,
            minor,
            patch,
        }
    }

    /// Parse from an u32
    pub fn parse(from: u32) -> SrtVersion {
        SrtVersion {
            major: (from / 0x10000) as u8,
            minor: ((from / 0x100) % 0x100) as u8,
            patch: (from % 0x100) as u8,
        }
    }

    /// Convert to an u32
    pub fn to_u32(self) -> u32 {
        u32::from(self.major) * 0x10000 + u32::from(self.minor) * 0x100 + u32::from(self.patch)
    }
}

impl PartialOrd for SrtVersion {
    fn partial_cmp(&self, other: &SrtVersion) -> Option<Ordering> {
        Some(match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => self.patch.cmp(&other.patch),
                o => o,
            },
            o => o,
        })
    }
}

impl Ord for SrtVersion {
    fn cmp(&self, other: &SrtVersion) -> Ordering {
        self.partial_cmp(other).unwrap() // this cannot fail
    }
}

impl fmt::Display for SrtVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl fmt::Debug for SrtVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}
