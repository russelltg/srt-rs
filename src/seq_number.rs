use std::{cmp::{Ord, Ordering},
          ops::{Add, AddAssign, Rem, Sub}};

use rand::{thread_rng, Rng};

// The maximum sequence number is all ones but starts with a zero
const MAX_SEQ_NUM: i32 = 0x7FFFFFFF;

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct SeqNumber(pub i32);

impl SeqNumber {
    /// Generate a random sequence number
    /// Guaranteed to be in the bounds of a sequence number
    pub fn random() -> SeqNumber {
        SeqNumber(0) + thread_rng().gen::<i32>().abs()
    }
}

impl Add<i32> for SeqNumber {
    type Output = Self;

    fn add(self, other: i32) -> SeqNumber {
        if other < 0 {
            return self - -other;
        }

        if MAX_SEQ_NUM - self.0 >= other {
            // no need to loop
            SeqNumber(self.0 + other)
        } else {
            // loop it
            SeqNumber(self.0 - MAX_SEQ_NUM + other - 1)
        }
    }
}

impl Sub<i32> for SeqNumber {
    type Output = Self;

    fn sub(self, other: i32) -> SeqNumber {
        if other < 0 {
            return self + -other;
        }

        if self.0 < other {
            // need to wrap
            SeqNumber(MAX_SEQ_NUM - other + self.0)
        } else {
            SeqNumber(self.0 - other)
        }
    }
}

// Distance between two SeqNumber's
impl Sub<SeqNumber> for SeqNumber {
    type Output = i32;

    fn sub(self, other: SeqNumber) -> i32 {
        // if this is true, assume there is no looping, and we can treat them as regular integers
        if (self.0 - other.0).abs() < 0x1FFFFFFF {
            self.0 - other.0
        } else {
            // here, there's looping going on.
            // ie: self may be MAX_SEQ_NUM - 1
            // and other could be 1
            if self.0 > other.0 {
                MAX_SEQ_NUM - (self.0 - other.0)
            } else {
                -(MAX_SEQ_NUM - (other.0 - self.0))
            }
        }
    }
}

impl Ord for SeqNumber {
    fn cmp(&self, other: &SeqNumber) -> Ordering {
        // this code is a bit tricky, and taken from the original implementation
        // I think !0 >> 3 is decided to be "if they're this far apart, they must be looped"
        // which is fair
        if (self.0 - other.0).abs() < 0x1FFFFFFF {
            self.0.cmp(&other.0)
        } else {
            other.0.cmp(&self.0)
        }
    }
}

impl Rem<i32> for SeqNumber {
    type Output = i32;

    fn rem(self, other: i32) -> i32 {
        self.0 % other
    }
}

impl PartialOrd for SeqNumber {
    fn partial_cmp(&self, other: &SeqNumber) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl AddAssign<i32> for SeqNumber {
    fn add_assign(&mut self, rhs: i32) {
        *self = *self + rhs
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
    assert_eq!(SeqNumber(MAX_SEQ_NUM) + 1, SeqNumber(0));
    assert_eq!(
        SeqNumber(MAX_SEQ_NUM - 10) - (MAX_SEQ_NUM - 50),
        SeqNumber(40)
    );
    assert_eq!(SeqNumber(4) - 10, SeqNumber(MAX_SEQ_NUM - 6));
    assert_eq!(SeqNumber(5) - SeqNumber(1), 4);
    assert_eq!(SeqNumber(MAX_SEQ_NUM - 1) - SeqNumber(1), 2);
}
