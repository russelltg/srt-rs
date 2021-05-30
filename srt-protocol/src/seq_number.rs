use std::iter::successors;

use crate::modular_num;

modular_num! {
    pub SeqNumber(u32, 31)
}

impl SeqNumber {
    pub fn increment(&mut self) -> SeqNumber {
        let result = *self;
        *self += 1;
        result
    }
}

pub fn seq_num_range(begin: SeqNumber, past_end: SeqNumber) -> impl Iterator<Item = SeqNumber> {
    successors(Some(begin), move |prev| {
        if *prev == past_end {
            None
        } else {
            Some(*prev + 1)
        }
    })
}
