use std::{fmt, cmp::{Ord, Ordering}, ops::{Add, AddAssign, Rem, Sub}};

use rand::{Rand, Rng};

// The maximum sequence number is all ones but starts with a zero
// this is the max seq num + 1
const MAX_SEQ_NUM: u32 = 0x80000000;
const MAX_DIFF: u32 = 0x1FFFFFFF;

modular_num! {
	pub SeqNumber(u32, 31)
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

