CFLAGS = -O0 -g
LIBSRT = ../target/debug/libsrt_c.a
SRT_H  = srtrs.h

.PHONY: all clean

all: examples/test-c-client examples/test-c-server

clean: 
	rm -f examples/test-c-client srtrs.h

$(LIBSRT): src/lib.rs
	cargo build --package srt-c --lib

$(SRT_H): cbindgen.toml src/lib.rs src/epoll.rs src/errors.rs src/socket.rs
	cbindgen --config cbindgen.toml --crate srt-c --output srtrs.h

examples/test-c-client: examples/test-c-client.cpp $(SRT_H) $(LIBSRT)
	g++ $(CFLAGS) examples/test-c-client.cpp -L ../target/debug -l:libsrt_c.a -lpthread -lm -ldl -o examples/test-c-client 

examples/test-c-server: examples/test-c-server.cpp $(SRT_H) $(LIBSRT)
	g++ $(CFLAGS) examples/test-c-server.cpp -L ../target/debug -l:libsrt_c.a -lpthread -lm -ldl -o examples/test-c-server