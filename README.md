# UDP Payload Extractor

A C/pthreads packet-processing coursework tool by Amirali Moghadasi. It reads classic Ethernet PCAP files, extracts eligible UDP keys and writes one JSON object per packet in capture order.

## Build and run

On Linux, install a C compiler, Make and OpenSSL development headers (for example `build-essential libssl-dev` on Ubuntu):

```bash
make
./udp_payload_extractor capture.pcap output.jsonl 4
make test
```

The optional thread count is 1–256 (default 12). A dependency-free PCAP reader replaces the original libpcap requirement; OpenSSL supplies SHA-1.

## Packet and output contract

- Classic PCAP 2.4, either byte order, microsecond or nanosecond timestamp magic; Ethernet link type. PCAPNG is not supported.
- Ethernet/IPv4/UDP, with up to two VLAN tags. Fragmented, truncated and inconsistent-length packets are skipped or rejected as appropriate.
- Only source IPv4 addresses with the original assignment prefixes `10.10.*.*` or `20.20.*.*` qualify.
- The key consists of UDP payload bytes before the first `#`. Packets without that delimiter are ignored.
- Each key is hashed once with SHA-1 and then its raw 20-byte digest is rehashed 9,999 times, matching the original 10,000-iteration workload.

```json
{"key":"example","sha1":"40 hexadecimal characters"}
```

The new format is JSONL, replacing the original single JSON object. It preserves repeated keys and bounded memory use. Non-ASCII bytes are escaped as Latin-1 code points; recover raw bytes with `record['key'].encode('latin1')`. Quotes, backslashes and embedded NULs are handled correctly. Work is processed in batches of at most 512 keys, with deterministic output independent of worker count. Input and output cannot refer to the same file.

## Verification

C tests check packet boundaries, header lengths, fragments and filters. Python creates synthetic little- and big-endian captures and compares every digest with `hashlib`, checks serial/parallel equality, JSON escaping and truncated-file failure. No private packet captures are bundled. SHA-1 here reproduces a coursework workload, not a password-storage design.
