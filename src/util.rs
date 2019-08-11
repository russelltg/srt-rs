use failure::{bail, Error};
use futures::prelude::*;
use log::warn;
use pin_utils::unsafe_pinned;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::Packet;

pub async fn get_packet<T: Stream<Item = Result<(Packet, SocketAddr), Error>> + Unpin>(
    sock: &mut T,
) -> Result<(Packet, SocketAddr), Error> {
    loop {
        match sock.next().await {
            None => bail!("Failed to listen, connection closed"),
            Some(Ok(t)) => break Ok(t),
            Some(Err(e)) => warn!("Failed to parse packet: {:?}", e),
        }
    }
}

pub enum Selected<T, U> {
    Left(T),
    Right(U),
}

pub fn select_discard<T: Future, U: Future>(
    a: T,
    b: U,
) -> impl Future<Output = Selected<<T as Future>::Output, <U as Future>::Output>> {
    struct SelectDiscard<T, U> {
        a: T,
        b: U,
    }

    impl<T, U> SelectDiscard<T, U> {
        unsafe_pinned!(a: T);
        unsafe_pinned!(b: U);
    }

    impl<T: Future, U: Future> Future for SelectDiscard<T, U> {
        type Output = Selected<T::Output, U::Output>;

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
            if let Poll::Ready(a) = self.as_mut().a().poll(cx) {
                return Poll::Ready(Selected::Left(a));
            }
            if let Poll::Ready(b) = self.as_mut().b().poll(cx) {
                return Poll::Ready(Selected::Right(b));
            }

            Poll::Pending
        }
    }

    SelectDiscard { a, b }
}
