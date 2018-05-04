use std::cmp::Ordering;

/// Serialied, it looks like:
/// major * 0x10000 + minor * 0x100 + patch
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct SrtVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

impl SrtVersion {
    /// Parse from an i32
    pub fn parse(from: i32) -> SrtVersion {
        SrtVersion {
            major: (from / 0x10000) as u8,
            minor: ((from / 0x100) % 0x100) as u8,
            patch: (from % 0x100) as u8,
        }
    }

    /// Convert to an i32
    pub fn to_i32(&self) -> i32 {
        self.major as i32 * 0x10000 + self.minor as i32 * 0x100 + self.patch as i32
    }
}

impl PartialOrd for SrtVersion {
    fn partial_cmp(&self, other: &SrtVersion) -> Option<Ordering> {
        Some(match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => self.patch.cmp(&other.patch),
                o @ _ => o,
            },
            o @ _ => o,
        })
    }
}

impl Ord for SrtVersion {
    fn cmp(&self, other: &SrtVersion) -> Ordering {
        self.partial_cmp(other).unwrap() // this cannot fail
    }
}
