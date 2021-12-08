use std::time::Duration;

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receiver {
    /// SRTO_RCVLATENCY
    ///
    /// The latency value in the receiving direction of the socket. This value is only significant when
    /// SRTO_TSBPDMODE is enabled.
    ///
    /// Default value: 120 ms in Live mode, 0 in File mode (see SRTO_TRANSTYPE).
    ///
    /// The latency value defines the minimum receiver buffering delay before delivering an SRT data
    /// packet from a receiving SRT socket to a receiving application. The provided value is used in
    /// the connection establishment (handshake exchange) stage to fix the end-to-end latency of the
    /// transmission. The effective end-to-end latency L will be fixed as the network transmission time
    /// of the final handshake packet (~1/2 RTT) plus the negotiated latency value Ln. Data packets will
    /// stay in the receiver buffer for at least L microseconds since the timestamp of the packet,
    /// independent of the actual network transmission times (RTT variations) of these packets.
    ///
    /// The actual value of the receiver buffering delay Ln (the negotiated latency) used on a
    /// connection is determined by the negotiation in the connection establishment (handshake exchange)
    /// phase as the maximum of the SRTO_RCVLATENCY value and the value of SRTO_PEERLATENCY set by the
    /// peer.
    ///
    /// Reading the SRTO_RCVLATENCY value on a socket after the connection is established provides the
    /// actual (negotiated) latency value Ln.
    ///
    /// The receiver's buffer must be large enough to store the L segment of the stream, i.e. L ×
    /// Bitrate bytes. Refer to SRTO_RCVBUF.
    ///
    /// The sender's buffer must be large enough to store a packet up until it is either delivered (and
    /// acknowledged) or dropped by the sender due to it becoming too late to be delivered. In other
    /// words, D × Bitrate bytes, where D is the sender's drop delay value configured with
    /// SRTO_SNDDROPDELAY.
    ///
    /// Buffering of data packets on the receiving side makes it possible to recover from packet losses
    /// using the ARQ (Automatic Repeat Request) technique, and to deal with varying RTT times (network
    /// jitter) in the network, providing a (close to) constant end-to-end latency of the transmission.
    pub latency: Duration,

    /// SRTO_LOSSMAXTTL
    /// The value up to which the Reorder Tolerance may grow. The Reorder Tolerance is the number of
    /// packets that must follow the experienced "gap" in sequence numbers of incoming packets so
    /// that the loss report is sent (in the hope that the gap is due to packet reordering rather
    /// than because of loss). The value of Reorder Tolerance starts from 0 and is set to a greater
    /// value when packet reordering is detected This happens when a "belated" packet, with sequence
    /// number older than the latest received, has been received, but without retransmission flag.
    /// When this is detected the Reorder Tolerance is set to the value of the interval between
    /// latest sequence and this packet's sequence, but not more than the value set by
    /// SRTO_LOSSMAXTTL. By default this value is set to 0, which means that this mechanism is off.
    pub reorder_tolerance_max: PacketCount,

    /// SRTO_RCVBUF
    ///
    /// Receive Buffer Size, in bytes. Note, however, that the internal setting of this value is in
    /// the number of buffers, each one of size equal to SRT payload size, which is the value of
    /// SRTO_MSS decreased by UDP and SRT header sizes (28 and 16). The value set here will be
    /// effectively aligned to the multiple of payload size.
    ///
    /// Minimum value: 32 buffers (46592 with default value of SRTO_MSS).
    ///
    /// Maximum value: SRTO_FC number of buffers (receiver buffer must not be greater than the
    /// Flight Flag size).
    pub buffer_size: ByteCount,

    /// SRTO_NAKREPORT
    /// When set to true, every report for a detected loss will be repeated when the timeout for the
    /// expected retransmission of this loss has expired and the missing packet still wasn't
    /// recovered, or wasn't conditionally dropped (see SRTO_TLPKTDROP).
    ///
    /// The default is true for Live mode
    pub nak_report: bool,

    ///SRTO_TLPKTDROP
    /// Too-late Packet Drop. When enabled on receiver, it skips missing packets that have not been
    /// delivered in time and delivers the subsequent packets to the application when their
    /// time-to-play has come. It also sends a fake ACK to the sender. When enabled on sender and
    /// enabled on the receiving peer, sender drops the older packets that have no chance to be
    /// delivered in time. It is automatically enabled in sender if receiver supports it.
    pub too_late_packet_drop: bool,

    // TODO: What is drift tracer?
    /// SRTO_DRIFTTRACER - Enable/disable drift tracer - unit: bool, default: true, range: t|f
    /// Enables or disables time drift tracer (receiver).
    pub drift_tracer: bool,
}

impl Default for Receiver {
    fn default() -> Self {
        Self {
            latency: Duration::from_millis(120),
            reorder_tolerance_max: PacketCount(0),
            buffer_size: ByteCount(8192 * 1500),
            nak_report: true,
            too_late_packet_drop: true,
            drift_tracer: false,
        }
    }
}

impl Validation for Receiver {
    type Error = OptionsError;

    fn is_valid(&self) -> Result<(), Self::Error> {
        use OptionsError::*;
        if self.buffer_size < ByteCount(46592) {
            Err(ReceiveBufferMin(self.buffer_size))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use OptionsError::*;

    #[test]
    fn validation() {
        let result = Receiver {
            buffer_size: ByteCount(46591),
            ..Default::default()
        };

        assert_eq!(
            result.try_validate(),
            Err(ReceiveBufferMin(ByteCount(46591)))
        );
    }
}
