use crate::modular_num;

modular_num! {
    pub MsgNumber(u32, 26)
}

impl MsgNumber {
    /// Increment self and return the old value
    pub fn increment(&mut self) -> MsgNumber {
        let result = *self;
        *self += 1;
        result
    }
}
