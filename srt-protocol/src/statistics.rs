use std::time::Duration;

/// SRT provides a powerful set of statistical data on a socket. This data can be used to keep an eye
/// on a socket's health and track faulty behavior.
///
/// Statistics are calculated independently on each side (receiver and sender) and are not exchanged
/// between peers unless explicitly stated.
#[derive(Debug, Eq, PartialEq, Default, Clone)]
pub struct SocketStatistics {
    /// The time elapsed, in milliseconds, since the SRT socket was created.
    pub elapsed_time: Duration, // msTimeStamp

    pub tx_all_packets: u64,
    pub rx_all_packets: u64,

    pub tx_all_bytes: u64,
    pub rx_all_bytes: u64,

    pub tx_encrypted_data: u64,
    pub rx_decrypted_data: u64,

    pub rx_clock_adjustments: u64,
    pub rx_clock_drift_mean: i64,
    pub rx_clock_drift_stddev: i64,

    pub rx_ack2_errors: i64,

    /// The total number of sent DATA packets, including retransmissions ([tx_retransmit_data](#tx_retransmit_data)).
    //
    //  TODO: Should we do this too?
    //   If the SRTO_PACKETFILTER socket option is enabled (refer to SRT API Socket Options), this statistic counts sent packet filter control packets (pktSndFilterExtraTotal) as well. Introduced in SRT v1.4.0.
    pub tx_data: u64, // pktSentTotal

    /// The total number of received DATA packets, including retransmissions ([rx_retransmit_data](#tx_retransmit_data)).
    //
    //  TODO: Should we do this too?
    //   If the `SRTO_PACKETFILTER` socket option is enabled (refer to [SRT API Socket Options](API-socket-options.md)), this statistic counts received packet filter control packets ([pktRcvFilterExtraTotal](#pktRcvFilterExtraTotal)) as well. Introduced in SRT v1.4.0.
    pub rx_data: u64, // pktRecvTotal

    /// The total number of sent *unique* DATA packets.
    ///
    /// This value contains only *unique* *original* DATA packets. Retransmitted DATA packets
    /// ([tx_retransmit_data](#tx_retransmit_data)) are not taken into account.
    ///
    /// This value corresponds to the number of original DATA packets sent by the SRT sender. It
    /// counts every packet sent over the network for the first time, and can be calculated as
    /// follows: `tx_unique_data = tx_data – tx_retransmit_data`. The original DATA packets are sent
    /// only once.
    //
    //  TODO: Should we do this?
    //   or by `pktSentUniqueTotal = pktSentTotal – pktRetransTotal - pktSndFilterExtraTotal` if the  `SRTO_PACKETFILTER` socket option is enabled
    //   If the `SRTO_PACKETFILTER` socket option is enabled (refer to [SRT API Socket Options](API-socket-options.md)), packet filter control packets ([pktSndFilterExtraTotal](#pktSndFilterExtraTotal)) are also not taken into account.
    pub tx_unique_data: u64, // pktSentUniqueTotal

    /// The total number of received *unique* original, retransmitted or recovered DATA packets
    /// *received in time*, *decrypted without errors* and, as a result, scheduled for delivery to
    /// the upstream application by the SRT receiver.
    ///
    /// Unique means "first arrived" DATA packets. There is no difference whether a packet is
    /// original or, in case of loss, retransmitted or recovered by the packet filter. Whichever
    /// packet comes first is taken into account.
    ///
    /// This statistic doesn't count
    ///
    /// - duplicate packets (retransmitted or sent several times by defective hardware/software),
    /// - arrived too late packets (retransmitted or original packets arrived out of order) that
    ///   were already dropped by the TLPKTDROP mechanism (see [tx_dropped_data](#tx_dropped_data)
    ///   statistic),
    /// - arrived in time packets, but decrypted with errors (see [rx_decrypt_errors](#rx_decrypt_errors)
    ///   statistic), and, as a result, dropped by the TLPKTDROP mechanism (see [tx_dropped_data](#tx_dropped_data)
    ///   statistic).
    //
    //  TODO: Should we do this?
    //   DATA packets recovered by the packet filter ([pktRcvFilterSupplyTotal](#pktRcvFilterSupplyTotal)) are taken into account if the `SRTO_PACKETFILTER` socket option is enabled (refer to [SRT API Socket Options](API-socket-options.md)). Do not mix up with the control packets received by the packet filter ([pktRcvFilterExtraTotal](#pktRcvFilterExtraTotal)).
    pub rx_unique_data: u64, // pktRecvUniqueTotal

    /// The total number of data packets considered or reported as lost at the sender side. Does not
    /// correspond to the packets detected as lost at the receiver side.
    ///
    /// A packet is considered lost in two cases:
    /// 1. Sender receives a loss report (NAK) from a receiver.
    /// 2. Sender initiates retransmission after not receiving an ACK packet for a certain timeout.
    /// Refer to `FASTREXMIT` and `LATEREXMIT` algorithms.
    pub tx_loss_data: u64, // pktSndLossTotal

    /// The total number of SRT DATA packets detected as presently missing (either reordered or lost)
    /// at the receiver side.
    ///
    /// The detection of presently missing packets is triggered by a newly received DATA packet with
    /// the sequence number `s`. If `s` is greater than the sequence number `next_exp` of the next
    /// expected packet (`s > next_exp`), the newly arrived packet `s` is considered in-order and
    /// there is a sequence discontinuity of size `s - next_exp` associated with this packet. The
    /// presence of sequence discontinuity means that some packets of the original sequence have
    /// not yet arrived (presently missing), either reordered or lost. Once the sequence discontinuity
    /// is detected, its size `s - next_exp` is added to `rx_loss_data` statistic. Refer to
    /// [RFC 4737 - Packet Reordering Metrics](https://tools.ietf.org/html/rfc4737) for details.
    ///
    /// If the packet `s` is received out of order (`s < next_exp`), the statistic is not affected.
    ///
    /// Note that only original (not retransmitted) SRT DATA packets are taken into account. Refer to
    /// [rx_retransmit_data](#rx_retransmit_data) for the formula for obtaining the total number of
    /// lost retransmitted packets.
    //
    // TODO: ensure this is implemented correctly
    //  In SRT v1.4.0, v1.4.1, the `pktRcvLossTotal` statistic includes packets that failed to be decrypted. To receive the number of presently missing packets, substract [pktRcvUndecryptTotal](#pktRcvUndecryptTotal) from the current one. This is going to be fixed in SRT v.1.5.0.
    pub rx_loss_data: u64, // pktRcvLossTotal

    /// The total number of retransmitted packets sent by the SRT sender.
    ///
    /// This statistic is not interchangeable with the receiver [rx_retransmit_data](#rx_retransmit_data)
    /// statistic.
    pub tx_retransmit_data: u64, // pktRetransTotal

    /// The total number of retransmitted packets registered at the receiver side.
    ///
    /// This statistic is not interchangeable with the sender [tx_retransmit_data](#tx_retransmit_data)
    /// statistic.
    ///
    /// Note that the total number of lost retransmitted packets can be calculated as the total
    /// number of retransmitted packets sent by receiver minus the total number of retransmitted
    /// packets registered at the receiver side:  `tx_retransmit_data - rx_retransmit_data`.
    //
    // TODO: ensure this is implemented correctly
    //  This is going to be implemented in SRT v1.5.0, see issue [#1208](https://github.com/Haivision/srt/issues/1208).
    pub rx_retransmit_data: u64, // pktRcvRetransTotal

    /// The total number of sent ACK (Acknowledgement) control packets.
    pub tx_ack: u64, // pktSentACKTotal

    /// The total number of received ACK (Acknowledgement) control packets.
    pub rx_ack: u64, // pktRecvACKTotal

    pub tx_light_ack: u64,

    pub rx_light_ack: u64,

    /// The total number of sent NAK (Negative Acknowledgement) control packets.
    pub tx_nak: u64, // pktSentNAKTotal

    /// The total number of received NAK (Negative Acknowledgement) control packets.
    pub rx_nak: u64, // pktRecvNAKTotal

    /// The total number of sent ACK2 (Acknowledgement Acknowledgement) control packets.
    pub tx_ack2: u64,

    /// The total number of received ACK2 (Acknowledgement Acknowledgement) control packets.
    pub rx_ack2: u64,

    /// The total accumulated time, during which the SRT sender has some data to
    /// transmit, including packets that have been sent, but not yet acknowledged. In other words,
    /// the total accumulated duration in microseconds when there was something to deliver (non-empty
    /// senders' buffer).
    pub tx_buffer_time: Duration, // usSndDurationTotal

    /// The total number of DATA packets _dropped_ by the SRT sender that have no chance to be
    /// delivered in time (refer to [TLPKTDROP](https://github.com/Haivision/srt-rfc/blob/master/draft-sharabayko-mops-srt.md#too-late-packet-drop-too-late-packet-drop)
    /// mechanism).
    ///
    /// Packets may be dropped conditionally when both `SRTO_TSBPDMODE` and `SRTO_TLPKTDROP` socket
    /// options are enabled, refer to [SRT API Socket Options](API-socket-options.md).
    ///
    /// The delay before TLPKTDROP mechanism is triggered is calculated as follows
    /// `SRTO_PEERLATENCY + SRTO_SNDDROPDELAY + 2 * interval between sending ACKs`,
    /// where `SRTO_PEERLATENCY` is the configured SRT latency, `SRTO_SNDDROPDELAY` adds an extra to
    /// `SRTO_PEERLATENCY` delay, the default `interval between sending ACKs` is 10 milliseconds. The
    /// minimum delay is `1000 + 2 * interval between sending ACKs` milliseconds.
    //
    // TODO: Should we provide these configuration options?
    // Refer to `SRTO_PEERLATENCY`, `SRTO_SNDDROPDELAY` socket options in [SRT API Socket Options](API-socket-options.md).
    pub tx_dropped_data: u64, // pktSndDropTotal

    /// The total number of DATA packets _dropped_ by the SRT receiver and, as a result, not delivered to the upstream application (refer to [TLPKTDROP](https://github.com/Haivision/srt-rfc/blob/master/draft-sharabayko-mops-srt.md#too-late-packet-drop-too-late-packet-drop) mechanism).
    ///
    /// This statistic counts
    /// - arrived too late packets (retransmitted or original packets arrived out of order),
    /// - arrived in time packets, but decrypted with errors (see also [rx_decrypt_errors](#rx_decrypt_errors) statistic).
    //
    // TODO: Should we provide these configuration options?
    // Packets may be dropped conditionally when both `SRTO_TSBPDMODE` and `SRTO_TLPKTDROP` socket options are enabled, refer to [SRT API Socket Options](API-socket-options.md).
    pub rx_dropped_data: u64, // pktRcvDropTotal

    /// The total number of packets that failed to be decrypted at the receiver side.
    pub rx_decrypt_errors: u64, // pktRcvUndecryptTotal

    // The total number of packet filter control packets generated by the packet filter (refer to [SRT Packet Filtering & FEC](../features/packet-filtering-and-fec.md)).
    //
    // Packet filter control packets contain only control information necessary for the packet filter. The type of these packets is DATA.
    //
    // If the `SRTO_PACKETFILTER` socket option is disabled (refer to [SRT API Socket Options](API-socket-options.md)), this statistic is equal to 0. Introduced in SRT v1.4.0.
    //
    // TODO: this probably won't be implemented; extensible packet filtering seems like over engineering
    // #### pktSndFilterExtraTotal

    // The total number of packet filter control packets received by the packet filter (refer to [SRT Packet Filtering & FEC](../features/packet-filtering-and-fec.md)).
    //
    // Packet filter control packets contain only control information necessary for the packet filter. The type of these packets is DATA.
    //
    // If the `SRTO_PACKETFILTER` socket option is disabled (refer to [SRT API Socket Options](API-socket-options.md)), this statistic is equal to 0. Introduced in SRT v1.4.0.
    //
    // TODO: this probably won't be implemented; extensible packet filtering seems like over engineering
    // #### pktRcvFilterExtraTotal

    // The total number of lost DATA packets recovered by the packet filter at the receiver side (e.g., FEC rebuilt packets; refer to [SRT Packet Filtering & FEC](../features/packet-filtering-and-fec.md)).
    //
    // If the `SRTO_PACKETFILTER` socket option is disabled (refer to [SRT API Socket Options](API-socket-options.md)), this statistic is equal to 0. Introduced in SRT v1.4.0.
    //
    // TODO: this probably won't be implemented; extensible packet filtering seems like over engineering
    // #### pktRcvFilterSupplyTotal

    // The total number of lost DATA packets **not** recovered by the packet filter at the receiver side (refer to [SRT Packet Filtering & FEC](../features/packet-filtering-and-fec.md)).
    //
    // If the `SRTO_PACKETFILTER` socket option is disabled (refer to [SRT API Socket Options](API-socket-options.md)), this statistic is equal to 0. Introduced in SRT v1.4.0.
    //
    // TODO: this probably won't be implemented; extensible packet filtering seems like over engineering
    // #### pktRcvFilterLossTotal
    /// Same as [tx_data](#tx_data), but expressed in bytes, including payload and all the headers
    /// (20 bytes IPv4 + 8 bytes UDP + 16 bytes SRT).
    pub tx_bytes: u64, // byteSentTotal

    /// Same as [rx_data](#rx_data), but expressed in bytes, including payload and all the headers
    /// (20 bytes IPv4 + 8 bytes UDP + 16 bytes SRT).
    pub rx_bytes: u64, // byteRecvTotal

    /// Same as [tx_unique_data](#tx_unique_data), but expressed in bytes, including payload and all
    /// the headers (20 bytes IPv4 + 8 bytes UDP + 16 bytes SRT).
    pub tx_unique_bytes: u64, // byteSentUniqueTotal

    /// Same as [rx_unique_data](#tx_unique_data), but expressed in bytes, including payload and all
    /// the headers (20 bytes IPv4 + 8 bytes UDP + 16 bytes SRT).
    pub rx_unique_bytes: u64, // byteRecvUniqueTotal

    /// Same as [rx_loss_data](#rx_loss_data), but expressed in bytes, including payload and all the
    /// headers (20 bytes IPv4 + 8 bytes UDP + 16 bytes SRT). Bytes for the presently missing (either
    /// reordered or lost) packets' payloads are estimated based on the average packet size.
    pub rx_loss_bytes: u64, // byteRcvLossTotal

    /// Same as [tx_retransmit_data](#tx_retransmit_data), but expressed in bytes, including payload
    /// and all the headers (20 bytes IPv4 + 8 bytes UDP + 16 bytes SRT).
    pub tx_retransmit_bytes: u64, // byteRetransTotal

    /// Same as [tx_dropped_data](#tx_dropped_data), but expressed in bytes, including payload and
    /// all the headers (20 bytes IPv4 + 8 bytes UDP + 16 bytes SRT).
    pub tx_dropped_bytes: u64, // byteSndDropTotal

    /// Same as [rx_dropped_data](#rx_dropped_data), but expressed in bytes, including payload and
    /// all the headers (20 bytes IPv4 + 8 bytes UDP + 16 bytes SRT). Bytes for the dropped packets'
    /// payloads are estimated based on the average packet size.
    // TODO: do we really need this?
    //  this could be calculated based on rx_dropped_data * (tx_data_bytes / tx_data)
    pub rx_dropped_bytes: u64, // byteRcvDropTotal

    /// Same as [rx_decrypt_errors](#rx_decrypt_errors), but expressed in bytes, including payload
    /// and all the headers (20 bytes IPv4 + 8 bytes UDP + 16 bytes SRT).
    pub rx_decrypt_error_bytes: u64, // byteRcvUndecryptTotal

    /// Current minimum time interval between which consecutive packets are sent microseconds.
    ///
    /// The `tx_snd_period` is the minimum time (sending period) that must be kept between two
    /// packets sent consecutively over the link used by an SRT socket. It is not the EXACT time
    /// interval between two consecutive packets. In the case where the time spent by an application
    /// between sending two consecutive packets exceeds `tx_snd_period`, the next packet will be
    /// sent faster, or even immediately, to preserve the average sending rate.
    ///
    /// **Note**: Does not apply to probing packets.
    // TODO: This isn't true, should it be?
    //  Note that several sockets sharing one outgoing port use the same sending queue.
    //  They may have different pacing of the outgoing packets, but all the packets will
    //  be placed in the same sending queue, which may affect the send timing.
    pub tx_snd_period: Duration, // usPktSndPeriod

    /// The maximum number of packets that can be "in flight".
    ///  See also [tx_unacknowledged_data](#tx_unacknowledged_data).
    ///
    /// The value retrieved on the sender side represents an estimation of the amount of free space
    /// in the buffer of the peer receiver. The actual amount of available space is periodically
    /// reported back by the receiver in ACK packets. When this value drops to zero, the next packet
    /// sent will be dropped by the receiver without processing. The receiver buffer contents should
    /// normally occupy no more than half of the buffer size (default 8192). If `tx_flow_window`
    /// value is less than that and becomes even less in the next reports, it means that the receiver
    /// application on the peer side cannot process the incoming stream fast enough and this may lead
    /// to a dropped connection.
    //
    // TODO: Should we implement this?
    //  In **file mode** this may cause a slowdown of sending in
    //  order to wait until the receiver has more space available, after it
    //  eventually extracts the packets waiting in its receiver buffer; in **live
    //  mode**
    pub tx_flow_window: u64, // pktFlowWindow

    // Congestion window size, in number of packets.
    //
    // Dynamically limits the maximum number of packets that can be in flight.
    // Congestion control module dynamically changes the value.
    //
    // In **file mode**  this value starts at 16 and is increased to the number of reported
    // acknowledged packets. This value is also updated based on the delivery rate, reported by the
    // receiver. It represents the maximum number of packets that can be safely sent without causing
    // network congestion. The higher this value is, the faster the packets can be sent.
    // In **live mode** this field is not used.
    // TODO: Should we implement this?
    //  it's only for file mode
    // #### pktCongestionWindow
    /// The number of packets in flight, therefore `tx_unacknowledged_data <= tx_flow_window`.
    // TODO: Should we implement this?
    //  it's only for file mode
    // and `tx_unacknowledged_data <= pktCongestionWindow`
    ///
    /// This is the distance between the packet sequence number that was last reported by an ACK
    /// message and the sequence number of the latest packet sent (at the moment when the statistics
    /// are being read).
    ///
    /// **NOTE:** ACKs are received periodically (at least every 10 ms). This value is most accurate
    /// just after receiving an ACK and becomes a little exaggerated over time until the next ACK
    /// arrives. This is because with a new packet sent, while the ACK number stays the same for a
    /// moment, the value of `tx_unacknowledged_data` increases. But the exact number of packets
    /// arrived since the last ACK report is unknown. A new statistic might be added which only
    /// reports the distance between the ACK sequence and the sent sequence at the moment when an
    /// ACK arrives, and isn't updated until the next ACK arrives. The difference between this value
    /// and `tx_unacknowledged_data` would then reveal the number of packets with an unknown state
    /// at that moment.
    pub tx_unacknowledged_data: u64, // pktFlightSize

    /// Smoothed round-trip time (SRTT), an exponentially-weighted moving average (EWMA) of an
    /// endpoint's RTT samples, in milliseconds.
    ///
    /// See [Section 4.10. Round-Trip Time Estimation](https://tools.ietf.org/html/draft-sharabayko-srt-00#section-4.10)
    /// of the [SRT RFC](https://datatracker.ietf.org/doc/html/draft-sharabayko-srt-00)
    /// and [[RFC6298] Paxson, V., Allman, M., Chu, J., and M. Sargent, "Computing TCP's Retransmission Timer"](https://datatracker.ietf.org/doc/html/rfc6298)
    /// for more details.
    pub tx_average_rtt: Duration, // msRTT
    pub rx_average_rtt: Duration,

    /// Estimated bandwidth of the network link.
    ///
    /// The bandwidth is estimated at the receiver. The estimation is based on the time between two
    /// probing DATA packets. Every 16th data packet is sent immediately after the previous data
    /// packet. By measuring the delay between probe packets on arrival, it is possible to estimate
    /// the maximum available transmission rate, which is interpreted as the bandwidth of the link.
    /// The receiver then sends back a running average calculation to the sender with an ACK message.
    pub tx_bandwidth: u64, // mbpsBandwidth
    pub rx_bandwidth: u64,

    /// The available space in the sender's buffer.
    ///
    /// This value decreases with data scheduled for sending by the application, and increases with
    /// every ACK received from the receiver, after the packets are sent over the UDP link.
    pub tx_buffer_available_bytes: u64, // byteAvailSndBuf

    /// The available space in the receiver's buffer, in bytes.
    ///
    /// This value increases after the application extracts the data from the socket and decreases
    /// with every packet received from the sender over the UDP link.
    pub rx_buffer_available_bytes: u64, // byteAvailRcvBuf

    // Transmission bandwidth limit, in Mbps.
    // Usually this is the setting from
    // the `SRTO_MAXBW` option, which may include the value 0 (unlimited). Under certain
    // conditions a nonzero value might be be provided by a congestion
    // control module, although none of the built-in congestion control modules
    // currently use it.
    //
    // Refer to `SRTO_MAXBW` and `SRTO_INPUTBW` in [SRT API Socket Options](API-socket-options.md).
    // TODO: Should we implement this?
    //  it's not actually dynamic, is it? if not then it's uninteresting as a statistic.
    // #### mbpsMaxBW

    // Maximum Segment Size (MSS), in bytes.
    // Same as the value from the `SRTO_MSS` socket option.
    // Should not exceed the size of the maximum transmission unit (MTU), in bytes. Sender and Receiver.
    // The default size of the UDP packet used for transport,
    // including all possible headers (Ethernet, IP and UDP), is 1500 bytes.
    //
    // Refer to `SRTO_MSS` in [SRT API Socket Options](API-socket-options.md).
    // TODO: Should we implement this?
    //  it's not actually dynamic, is it? if not then it's uninteresting as a statistic.
    // #### byteMSS

    // The number of packets in the sender's buffer that are already scheduled for sending or even
    // possibly sent, but not yet acknowledged.
    //
    // Once the receiver acknowledges the receipt of a packet, or the too late packet drop is
    // triggered, the packet is removed from the sender's buffer. Until this happens, the packet is
    // considered as unacknowledged.
    // TODO: also calculate average
    pub tx_buffered_data: u64, // pktSndBuf

    // Instantaneous (current) value of `tx_buffered_data`, but expressed in bytes, including payload and
    // all headers (SRT+UDP+IP). \
    // 20 bytes IPv4 + 8 bytes of UDP + 16 bytes SRT header.
    // TODO: also calculate average
    pub tx_buffered_bytes: u64, // byteSndBuf

    // The timespan of packets in the sender's buffer.
    // TODO: also calculate average
    pub tx_buffered_time: Duration, // msSndBuf

    // Timestamp-based Packet Delivery Delay value of the peer.
    // If `SRTO_TSBPDMODE` is on (default for **live mode**), it
    // returns the value of `SRTO_PEERLATENCY`, otherwise 0.
    // The sender reports the TSBPD delay value of the receiver.
    // The receiver reports the TSBPD delay of the sender.
    // TODO: Should we implement this?
    //  it's not actually dynamic, is it? if not then it's uninteresting as a statistic.
    // #### msSndTsbPdDelay
    /// The number of acknowledged packets in receiver's buffer.
    ///
    /// This measurement does not include received but not acknowledged packets, stored in the
    /// receiver's buffer.
    // TODO: also calculate average
    pub rx_acknowledged_data: u64, // pktRcvBuf

    /// Instantaneous (current) value of `pktRcvBuf`, expressed in bytes, including payload and all
    /// headers (SRT+UDP+IP). \
    /// 20 bytes IPv4 + 8 bytes of UDP + 16 bytes SRT header.
    // TODO: also calculate average
    pub rx_acknowledged_bytes: u64, // byteRcvBuf

    /// The timespan of acknowledged packets in the receiver's buffer.
    ///
    /// A packet can be acknowledged, but not yet ready to play. This range includes all packets
    /// regardless of whether they are ready to play or not.
    /// TODO: also calculate average
    pub rx_acknowledged_time: Duration, // msRcvBuf

    // Timestamp-based Packet Delivery Delay value set on the socket via `SRTO_RCVLATENCY` or `SRTO_LATENCY`.
    // The value is used to apply TSBPD delay for reading the received data on the socket.
    //
    // If `SRTO_TSBPDMODE` is off (default for **file mode**), 0 is returned.
    // TODO: Should we implement this?
    //  it's not actually dynamic, is it? if not then it's uninteresting as a statistic.
    // #### msRcvTsbPdDelay

    // #### pktReorderDistance
    //
    // The distance in sequence numbers between the two original (not retransmitted) packets,
    // that were received out of order.
    // TODO: Should we implement this?
    //  should we even support maximum reorder tolerance?
    // The traceable distance values are limited by the maximum reorder tolerance set by  `SRTO_LOSSMAXTTL`.

    // Instant value of the packet reorder tolerance. Receiver side. Refer to [pktReorderDistance](#pktReorderDistance).
    //
    // `SRTO_LOSSMAXTTL` sets the maximum reorder tolerance value. The value defines the maximum
    // time-to-live for the original packet, that was received after with a gap in the sequence of incoming packets.
    // Those missing packets are expected to come out of order, therefore no loss is reported.
    // The actual TTL value (**pktReorderTolerance**) specifies the number of packets to receive further, before considering
    // the preceding packets lost, and sending the loss report.
    //
    // The internal algorithm checks the order of incoming packets and adjusts the tolerance based on the reorder
    // distance (**pktReorderTolerance**), but not to a value higher than the maximum (`SRTO_LOSSMAXTTL`).
    //
    // SRT starts from tolerance value set in `SRTO_LOSSMAXTTL` (initial tolerance is set to 0 in SRT v1.4.0 and prior versions).
    // Once the receiver receives the first reordered packet, it increases the tolerance to the distance in the sequence
    // discontinuity of the two packets. \
    // After 10 consecutive original (not retransmitted) packets come in order, the reorder distance
    // is decreased by 1 for every such packet.
    //
    // For example, assume packets with the following sequence
    // numbers are being received: \
    // 1, 2, 4, 3, 5, 7, 6, 10, 8, 9
    // SRT starts from 0 tolerance. Receiving packet with sequence number 4 has a discontinuity
    // equal to one packet. The loss is reported to the sender.
    // With the next packet (sequence number 3) a reordering is detected. Reorder tolerance is increased to 1. \
    // The next sequence discontinuity is detected when the packet with sequence number 7 is received.
    // The current tolerance value is 1, which is equal to the gap (between 5 and 7). No loss is reported. \
    // Next packet with sequence number 10 has a higher sequence discontinuity equal to 2.
    // Missing packets with sequence numbers 8 and 9 will be reported lost with the next received packet
    // (reorder distance is still at 1).
    // The next received packet has sequence number 8. Reorder tolerance value is increased to 2.
    // The packet with sequence number 9 is reported lost.
    // TODO: Should we implement this?
    //  I don't think we've implemented SRTO_LOSSMAXTTL yet, revisit this when/if we do
    // #### pktReorderTolerance
    /// The number of packets received but IGNORED due to having arrived too late.
    ///
    /// Makes sense only if TSBPD and TLPKTDROP are enabled.
    ///
    /// An offset between sequence numbers of the newly arrived DATA packet and latest acknowledged
    /// DATA packet is calculated. If the offset is negative, the packet is considered late, meaning
    /// that it was either already acknowledged or dropped by TSBPD as too late to be delivered.
    ///
    /// Retransmitted packets can also be considered late.
    pub rx_belated_data: u64, // pktRcvBelated

    /// Accumulated difference between the current time and the time-to-play of a packet that is
    /// received late.
    pub rx_belated_time: Duration, // pktRcvAvgBelatedTime
}

impl SocketStatistics {
    pub fn new() -> Self {
        Self::default()
    }
}
