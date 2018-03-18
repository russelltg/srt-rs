use receiver::Receiver;
use sender::Sender;

pub enum Connection {
    Recv(Receiver),
    Send(Sender),
}
