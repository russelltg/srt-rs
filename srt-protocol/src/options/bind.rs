use super::*;

pub enum BindOptions {
    Listen(Valid<ListenerOptions>),
    Call(Valid<CallerOptions>),
    Rendezvous(Valid<RendezvousOptions>),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn into() {
        let caller = CallerOptions::new("127.0.0.1:42", Some("stream ID"))
            .unwrap()
            .with(Connect::default())
            .unwrap()
            .with(Session::default())
            .unwrap()
            .with(Encryption::default())
            .unwrap()
            .with(Sender::default())
            .unwrap()
            .with(Receiver::default())
            .unwrap();

        let listener = ListenerOptions::new(42)
            .unwrap()
            .with(Connect::default())
            .unwrap()
            .with(Session::default())
            .unwrap()
            .with3(
                Encryption::default(),
                Sender::default(),
                Receiver::default(),
            )
            .unwrap();

        let rendezvous = RendezvousOptions::new("127.0.0.1:42")
            .unwrap()
            .with(Connect::default())
            .unwrap()
            .with(Session::default())
            .unwrap()
            .with(Encryption::default())
            .unwrap()
            .with2(Sender::default(), Receiver::default())
            .unwrap();

        let _: BindOptions = caller.into();
        let _: BindOptions = listener.into();
        let _: BindOptions = rendezvous.into();
    }
}
