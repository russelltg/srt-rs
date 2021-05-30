#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct FullAckSeqNumber(u32);

// See 3.2.3.  ACK (Acknowledgement)
// the sequential number of the full ACK packet starting from 1
impl FullAckSeqNumber {
    pub const MIN: FullAckSeqNumber = FullAckSeqNumber(1);
    pub const MAX: FullAckSeqNumber = FullAckSeqNumber(u32::MAX);

    pub fn from_u32(num: u32) -> Option<FullAckSeqNumber> {
        if num == 0 {
            None
        } else {
            Some(FullAckSeqNumber(num))
        }
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }

    pub fn increment(&mut self) -> FullAckSeqNumber {
        let result = *self;
        if result == Self::MAX {
            *self = Self::MIN;
        } else {
            self.0 += 1;
        }
        result
    }
}
