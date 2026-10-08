#include "packet.h"
#include <string.h>
static unsigned be16(const unsigned char *p) { return (unsigned)p[0] * 256 + p[1]; }
int extract_key(const unsigned char *packet, size_t captured,
                const unsigned char **key, size_t *length) {
    if (captured < 14) return 0;
    size_t offset = 14;
    unsigned type = be16(packet + 12);
    for (int tags = 0; (type == 0x8100 || type == 0x88a8) && tags < 2; ++tags) {
        if (captured < offset + 4) return 0;
        type = be16(packet + offset + 2); offset += 4;
    }
    if (type != 0x0800 || captured < offset + 20) return 0;
    const unsigned char *ip = packet + offset;
    size_t ihl = (ip[0] & 15u) * 4u;
    unsigned total = be16(ip + 2);
    if ((ip[0] >> 4) != 4 || ihl < 20 || total < ihl + 8 ||
        total > captured - offset || ip[9] != 17 || (be16(ip + 6) & 0x3fff)) return 0;
    if (!((ip[12] == 10 && ip[13] == 10) || (ip[12] == 20 && ip[13] == 20))) return 0;
    const unsigned char *udp = ip + ihl;
    unsigned udp_length = be16(udp + 4);
    if (udp_length < 8 || udp_length > total - ihl) return 0;
    const unsigned char *payload = udp + 8;
    size_t payload_length = udp_length - 8;
    const unsigned char *start = memchr(payload, '#', payload_length);
    if (!start) return 0;
    size_t remaining = payload_length - (size_t)(start + 1 - payload);
    const unsigned char *end = memchr(start + 1, '#', remaining);
    if (!end) return 0;
    *key = start + 1; *length = (size_t)(end - start - 1);
    return 1;
}
