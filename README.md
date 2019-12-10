# srt-rs

[![Build Status](https://travis-ci.org/russelltg/srt-rs.svg?branch=master)](https://travis-ci.org/russelltg/srt-rs) [![Build status](https://ci.appveyor.com/api/projects/status/q0eu7a4mtunff041?svg=true)](https://ci.appveyor.com/project/GuapoTaco/srt-rs) [![codecov](https://codecov.io/gh/russelltg/srt-rs/branch/master/graph/badge.svg)](https://codecov.io/gh/russelltg/srt-rs)

> NOTE: THIS IS NOT PRODUCTION READY.

Pure rust implementation of SRT (Secure Reliable Transport), without unsafe code.

Reference implementation is available at https://github.com/haivision/srt

# Features

- Fast (heap allocations are rare)
- Single-threaded

# What works

- [x] Listen server connecting
- [x] Client (connect) connecting
- [x] Rendezvous connecting
- [x] Receiving
- [x] Sending
- [x] Special SRT packets (partial)
- [x] Actual SRT (TSBPD)
- [ ] Timestamp drift recovery
- [ ] Encryption
- [x] Bidirectional

# Heap efficiency

Running under massif, the maximum memory usage is around 6KB for transmitting video. for srt-rs.

For the reference implementation, this number grows to 1.2MB, so around a 2X difference. 

# Thread Efficiency

The reference implementation of SRT requires 3 threads per sender and 5 threads per receiver. 

With srt-rs, you can assign as many connections to exactly as many threads as you want (usually as many as you have cores) using
Rust's futures scheduling.



