use super::*;

pub enum BindOptions {
    Listen(Valid<ListenerOptions>),
    Call(Valid<CallerOptions>),
    Rendezvous(Valid<RendezvousOptions>)
}

impl From<Valid<ListenerOptions>> for BindOptions {
    fn from(options: Valid<ListenerOptions>) -> Self {
        BindOptions::Listen(options)
    }
}

impl From<Valid<CallerOptions>> for BindOptions {
    fn from(options: Valid<CallerOptions>) -> Self {
        BindOptions::Call(options)
    }
}

impl From<Valid<RendezvousOptions>> for BindOptions {
    fn from(options: Valid<RendezvousOptions>) -> Self {
        BindOptions::Rendezvous(options)
    }
}