#ifndef CAPTURE_H
#define CAPTURE_H
#include <stdio.h>
#include <stddef.h>
typedef struct { FILE *file; int little; unsigned snaplen; } Capture;
int capture_open(Capture *capture, const char *path);
int capture_next(Capture *capture, unsigned char **packet, size_t *length);
void capture_close(Capture *capture);
#endif
