use std::iter::successors;

use crate::modular_num;

modular_num! {
    pub SeqNumber(u32, 31)
}

/// Exclusive sequence number range [start, end)
#[allow(dead_code)]
pub fn seq_num_range(start: SeqNumber, end: SeqNumber) -> impl Iterator<Item = SeqNumber> {
    successors(Some(start), move |prev| {
        if *prev + 1 == end {
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn seq_no_test() {
        assert_eq!(
            seq_num_range(SeqNumber(10), SeqNumber(12)).collect::<Vec<_>>(),
            vec![SeqNumber(10), SeqNumber(11)]
        );
    }
}
