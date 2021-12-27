CFLAGS = -O0 -g

.PHONY: all clean

all: examples/test-c-client

clean: 
	rm -f examples/test-c-client srtrs.h

../target/debug/libsrt_c.a: src/lib.rs
	cargo build --package srt-c --lib

srtrs.h: cbindgen.toml src/lib.rs
	cbindgen --config cbindgen.toml --crate srt-c --output srtrs.h

examples/test-c-client: examples/test-c-client.cpp srtrs.h ../target/debug/libsrt_c.a
	gcc $(CFLAGS) examples/test-c-client.cpp -L ../target/debug -l:libsrt_c.a -lpthread -lm -ldl -o examples/test-c-client 