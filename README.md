# srt-rs

| OS | Status |
| --- | --- |
| Linux | [![Build Status](https://russelltg.visualstudio.com/srt-rs/_apis/build/status/russelltg.srt-rs?branchName=master&stageName=Multi%20OS%20native%20tests&jobName=Cargo%20test&configuration=Cargo%20test%20Linux)](https://russelltg.visualstudio.com/srt-rs/_build/latest?definitionId=2&branchName=master) |
| macOS | [![Build Status](https://russelltg.visualstudio.com/srt-rs/_apis/build/status/russelltg.srt-rs?branchName=master&stageName=Multi%20OS%20native%20tests&jobName=Cargo%20test&configuration=Cargo%20test%20MacOS)](https://russelltg.visualstudio.com/srt-rs/_build/latest?definitionId=2&branchName=master) |
| Windows | [![Build Status](https://russelltg.visualstudio.com/srt-rs/_apis/build/status/russelltg.srt-rs?branchName=master&stageName=Multi%20OS%20native%20tests&jobName=Cargo%20test&configuration=Cargo%20test%20Windows)](https://russelltg.visualstudio.com/srt-rs/_build/latest?definitionId=2&branchName=master) |

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

For the reference implementation, this number grows to 1.2MB, so around a 200X difference. 

# Thread Efficiency

The reference implementation of SRT requires 3 threads per sender and 5 threads per receiver. 

With srt-rs, you can assign as many connections to exactly as many threads as you want (usually as many as you have cores) using
Rust's futures scheduling.



