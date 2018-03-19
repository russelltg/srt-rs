# srt-rs

Pure rust implementation of SRT (Secure Reliable Transport)

Reference implementation is available at https://github.com/haivision/srt

# Features

- Fast (heap allocations are rare)
- Single-threaded

# What works

- [x] Listen server connecting
- [ ] Client (connect) connecting
- [ ] Rendezvous connecting
- [x] Receiving
- [ ] Sending


# Heap efficiency

Running under massif, the maximum memory usage is around 6KB for transmitting video. for srt-rs.

For the reference implementation, this number grows to 1.2MB, so around a 2X difference. 

As far as allocations, 
