/* Classic PCAP reader: both endian orders and micro/nanosecond timestamp variants. */
#include "capture.h"
#include <stdlib.h>
#include <string.h>
static unsigned read32(const unsigned char *p, int little) {
    if (little) return (unsigned)p[0]|(unsigned)p[1]<<8|(unsigned)p[2]<<16|(unsigned)p[3]<<24;
    return (unsigned)p[3]|(unsigned)p[2]<<8|(unsigned)p[1]<<16|(unsigned)p[0]<<24;
}
int capture_open(Capture *capture, const char *path) {
    unsigned char header[24];
    memset(capture,0,sizeof(*capture));
    capture->file=fopen(path,"rb");
    if (!capture->file) return -1;
    if (fread(header,1,sizeof(header),capture->file)!=sizeof(header)) goto error;
    if (!memcmp(header,"\xd4\xc3\xb2\xa1",4) || !memcmp(header,"\x4d\x3c\xb2\xa1",4)) capture->little=1;
    else if (memcmp(header,"\xa1\xb2\xc3\xd4",4) && memcmp(header,"\xa1\xb2\x3c\x4d",4)) goto error;
    unsigned major=capture->little?header[4]|header[5]<<8:header[5]|header[4]<<8;
    unsigned minor=capture->little?header[6]|header[7]<<8:header[7]|header[6]<<8;
    if (major!=2 || minor!=4 || (read32(header+20,capture->little)&0xffff)!=1) goto error;
    capture->snaplen=read32(header+16,capture->little);
    if (!capture->snaplen || capture->snaplen>16*1024*1024) goto error;
    return 0;
error:
    capture_close(capture);return -1;
}
int capture_next(Capture *capture, unsigned char **packet, size_t *length) {
    unsigned char header[16];
    size_t n=fread(header,1,sizeof(header),capture->file);
    if (!n && feof(capture->file)) return 0;
    if (n!=sizeof(header)) return -1;
    unsigned captured=read32(header+8,capture->little), original=read32(header+12,capture->little);
    if (captured>capture->snaplen || captured>original) return -1;
    *packet=malloc(captured?captured:1);
    if (!*packet) return -1;
    if (fread(*packet,1,captured,capture->file)!=captured) { free(*packet); *packet=NULL; return -1; }
    *length=captured;return 1;
}
void capture_close(Capture *capture) {
    if (capture->file) fclose(capture->file);
    capture->file=NULL;
}
