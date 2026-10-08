#include "../src/packet.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
int main(void) {
    unsigned char packet[64] = {0};
    packet[12]=8; packet[14]=0x45; packet[17]=35; packet[23]=17;
    packet[26]=10; packet[27]=10; packet[39]=15;
    memcpy(packet+42,"#a\"b#xx",7);
    const unsigned char *key; size_t length;
    assert(extract_key(packet,49,&key,&length) && length==3);
    assert(!memcmp(key,"a\"b",3));
    for (size_t n=0;n<49;++n) assert(!extract_key(packet,n,&key,&length));
    packet[20]=0x20; assert(!extract_key(packet,49,&key,&length)); packet[20]=0;
    packet[39]=30; assert(!extract_key(packet,49,&key,&length)); packet[39]=15;
    packet[26]=30; assert(!extract_key(packet,49,&key,&length)); packet[26]=10;
    packet[46]='!'; assert(!extract_key(packet,49,&key,&length));
    puts("packet bounds/fragment/filter tests passed");
}
