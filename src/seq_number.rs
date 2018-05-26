
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

