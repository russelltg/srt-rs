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
        let [_, major, minor, patch] = from.to_be_bytes();
        SrtVersion {
            major,
            minor,
            patch,
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

#[cfg(test)]
mod test {
    use super::SrtVersion;
    #[test]
    fn test_parse() {
        assert_eq!(SrtVersion::parse(0x01_01_01), SrtVersion::new(1, 1, 1));
        assert_eq!(SrtVersion::parse(0x00_00_00), SrtVersion::new(0, 0, 0));
    }

    #[test]
    fn test_display_debug() {
        assert_eq!(format!("{}", SrtVersion::new(12, 12, 12)), "12.12.12");
        assert_eq!(format!("{:?}", SrtVersion::new(12, 12, 12)), "12.12.12");
    }
}
