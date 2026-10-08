#ifndef PACKET_H
#define PACKET_H
#include <stddef.h>
/* Returns the first #-delimited key from a captured Ethernet/IPv4/UDP frame. */
int extract_key(const unsigned char *packet, size_t captured,
                const unsigned char **key, size_t *length);
#endif
