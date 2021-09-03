use std::iter::successors;

use crate::modular_num;

modular_num! {
    pub SeqNumber(u32, 31)
}

#[allow(dead_code)]
pub fn seq_num_range(first: SeqNumber, last: SeqNumber) -> impl Iterator<Item = SeqNumber> {
    successors(Some(first), move |prev| {
        if *prev == last {
            None
        } else {
            Some(*prev + 1)
        }
    })
}

impl SeqNumber {
    #[must_use]
    pub fn increment(&mut self) -> Self {
        let next = *self;
        *self += 1;
        next
    }
}
