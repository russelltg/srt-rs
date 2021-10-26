use crate::modular_num;

modular_num! {
    pub SeqNumber(u32, 31)
}

impl SeqNumber {
    #[must_use]
    pub fn increment(&mut self) -> Self {
        let next = *self;
        *self += 1;
        next
    }
}
