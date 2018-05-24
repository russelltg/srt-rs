use std::{fmt, cmp::{Ord, Ordering}, ops::{Add, AddAssign, Rem, Sub}};

use rand::{Rand, Rng};

// The maximum sequence number is all ones but starts with a zero
// this is the max seq num + 1
const MAX_SEQ_NUM: u32 = 0x80000000;
const MAX_DIFF: u32 = 0x1FFFFFFF;

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct SeqNumber(u32);

impl SeqNumber {
    pub fn new(num: u32) -> SeqNumber {
        SeqNumber(num % MAX_SEQ_NUM)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl Rand for SeqNumber {
    fn rand<T: Rng>(rng: &mut T) -> SeqNumber {
        SeqNumber(0) + rng.gen::<u32>()
    }
}

impl Add<u32> for SeqNumber {
    type Output = Self;

    fn add(self, other: u32) -> SeqNumber {
        let added = u32::wrapping_add(self.0, other);

        SeqNumber(added % MAX_SEQ_NUM)
    }
}

/// Move a sequence number backwards by an offset
/// ie: SeqNumber(3) - 2 == 1
/// and SeqNumber(0) - 1 == SeqNumber(MAX_SEQ_NUM)
impl Sub<u32> for SeqNumber {
    type Output = Self;

    fn sub(self, other: u32) -> SeqNumber {
        if self.0 < other {
            // wrap
            SeqNumber(MAX_SEQ_NUM - (other - self.0))
        } else {
            SeqNumber(self.0 - other)
        }
    }
}

/// Gets the distance between two sequence numbers
/// Always measured with first one first and the second one second
/// ie: SeqNumber(0) - SeqNumber(MAX_SEQ_NUM) == 1
/// and SeqNumber(1) - SeqNumber(0) == 1
impl Sub<SeqNumber> for SeqNumber {
    type Output = u32;

    fn sub(self, other: SeqNumber) -> u32 {
        if self.0 > other.0 {
            // no wrap required
            self.0 - other.0
        } else {
            MAX_SEQ_NUM - (other.0 - self.0)
        }
    }
}

/// Ordering sequence numbers is difficult, as they are modular
/// How it works is if the absolute value of the difference between sequence numbers is greater than
/// MAX_DIFF, then wrapping is assumed
impl Ord for SeqNumber {
    fn cmp(&self, other: &SeqNumber) -> Ordering {
        let diff = *self - *other;

        if diff == 0 {
            return Ordering::Equal;
        }

        if diff < MAX_DIFF {
            // this means self was bigger than other
            Ordering::Greater
        } else {
            // this means other was greater
            Ordering::Less
        }
    }
}

impl Rem<u32> for SeqNumber {
    type Output = u32;

    fn rem(self, other: u32) -> u32 {
        self.0 % other
    }
}

impl PartialOrd for SeqNumber {
    fn partial_cmp(&self, other: &SeqNumber) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl AddAssign<u32> for SeqNumber {
    fn add_assign(&mut self, rhs: u32) {
        *self = *self + rhs
    }
}

impl fmt::Display for SeqNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub struct SeqNumberRange {
    current: SeqNumber,
    end: SeqNumber,
}

impl Iterator for SeqNumberRange {
    type Item = SeqNumber;

    fn next(&mut self) -> Option<SeqNumber> {
        let ret = if self.current == self.end {
            None
        } else {
            Some(self.current)
        };

        self.current += 1;

        ret
    }
}

pub fn seq_num_range(begin: SeqNumber, past_end: SeqNumber) -> SeqNumberRange {
    SeqNumberRange {
        current: begin,
        end: past_end,
    }
}

#[test]
fn seq_num_test() {
    assert_eq!(SeqNumber(14), SeqNumber(5) + 9);
    assert_eq!(SeqNumber(MAX_SEQ_NUM - 1) + 1, SeqNumber(0));
    assert_eq!(
        SeqNumber(MAX_SEQ_NUM - 10) - (MAX_SEQ_NUM - 50),
        SeqNumber(40)
    );
    assert_eq!(SeqNumber(4) - 10, SeqNumber(MAX_SEQ_NUM - 6));
    assert_eq!(SeqNumber(5) - SeqNumber(1), 4);
    assert_eq!(SeqNumber(2) - SeqNumber(MAX_SEQ_NUM - 1), 3);
}
