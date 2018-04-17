use {Sender};

use std::time::Duration;

struct StatsPrinterSender<T, CC> {
    sender: Sender<T, CC>
}

impl<T, CC> StatsPrinterSender<T, CC> {
    fn new(sender: Sender<T, CC>, interval: Duration) -> StatsPrinterSender<T, CC> {
        StatsPrinterSender { sender }
    }
}
