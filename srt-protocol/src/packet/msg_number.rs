use super::modular_num::modular_num;

modular_num! {
    pub MsgNumber(u32, 26)
}

impl MsgNumber {
    #[must_use]
    pub fn increment(&mut self) -> Self {
        let result = *self;
        *self += 1;
        result
    }
}
