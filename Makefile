CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=gnu11
all: udp_payload_extractor
udp_payload_extractor: src/udp_payload_extractor.c src/packet.c src/capture.c src/packet.h src/capture.h
	$(CC) $(CFLAGS) src/udp_payload_extractor.c src/packet.c src/capture.c -o $@ -lcrypto -pthread
test_packet: src/packet.c tests/test_packet.c
	$(CC) $(CFLAGS) src/packet.c tests/test_packet.c -o $@
test: all test_packet
	./test_packet
	python3 tests/integration.py
clean:
	rm -f udp_payload_extractor udp_payload_extractor.exe test_packet test_packet.exe
.PHONY: all test clean
