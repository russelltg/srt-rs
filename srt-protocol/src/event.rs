use std::time::{Duration, Instant};

#[non_exhaustive]
#[derive(Debug, Copy, Clone)]
pub enum Event {
    /// Sent a packet of the given size for the first time
    /// Only sent by sender
    Sent(usize),

    /// Sent a packet that's already been sent
    /// Only sent by sender
    SentRetrans(usize),

    /// Received a packet of the given size
    /// Only sent by receiver
    Recvd(usize),

    /// Received a packet that was initially lost
    RecvdRetrans(usize),

    /// When a packet is released
    Released(usize),

    /// Dropped a packet of a given size
    /// Only sent by receiver
    Dropped(usize),

    /// When the rtt is updated
    /// Sent by both receiver and sender
    RttUpdated(Duration),
}

/// Intercepts events that happen, for statistics
pub trait EventReceiver {
    /// Calls on the sender/receiver tasks, so make it quick!
    fn on_event(&mut self, event: &Event, timestamp: Instant);
}

impl<E: EventReceiver + ?Sized> EventReceiver for Box<E> {
    fn on_event(&mut self, event: &Event, timestamp: Instant) {
        (**self).on_event(event, timestamp)
    }
}

pub struct NullEventReceiver;
impl EventReceiver for NullEventReceiver {
    fn on_event(&mut self, _event: &Event, _timestamp: Instant) {}
}
