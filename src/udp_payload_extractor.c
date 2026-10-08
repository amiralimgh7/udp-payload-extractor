#include "packet.h"
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include "capture.h"
#include <pthread.h>
#include <openssl/sha.h>

#define BATCH_SIZE 512
#define HASH_ITERATIONS 10000
typedef struct { unsigned char *key; size_t length; unsigned char hash[SHA_DIGEST_LENGTH]; } Record;
typedef struct { Record *records; size_t count, start, stride; } Work;
static void *process(void *arg) {
    Work *work = arg;
    for (size_t i=work->start;i<work->count;i+=work->stride) {
        Record *r = &work->records[i];
        unsigned char temp[SHA_DIGEST_LENGTH];
        SHA1(r->key,r->length,r->hash);
        for (int j=1;j<HASH_ITERATIONS;++j) {
            SHA1(r->hash,SHA_DIGEST_LENGTH,temp); memcpy(r->hash,temp,sizeof(temp));
        }
    }
    return NULL;
}
static void write_json_key(FILE *out, const unsigned char *key, size_t length) {
    fputc('"',out);
    for (size_t i=0;i<length;++i) {
        unsigned char c=key[i];
        if (c=='"' || c=='\\') { fputc('\\',out); fputc(c,out); }
        else if (c<32 || c>=127) fprintf(out,"\\u%04x",(unsigned)c);
        else fputc(c,out);
    }
    fputc('"',out);
}
int main(int argc, char **argv) {
    if (argc<3 || argc>4) { fprintf(stderr,"Usage: %s input.pcap output.jsonl [threads]\n",argv[0]); return 1; }
    char *end=NULL;
    long count=argc==4?strtol(argv[3],&end,10):12;
    if (count<1 || count>256 || (argc==4 && (!*argv[3] || *end))) { fprintf(stderr,"threads must be 1..256\n"); return 1; }
    struct stat input_stat, output_stat;
    if (!stat(argv[1], &input_stat) && !stat(argv[2], &output_stat) &&
        input_stat.st_dev == output_stat.st_dev && input_stat.st_ino == output_stat.st_ino) {
        fprintf(stderr,"Input and output must be different files\n"); return 1;
    }
    Capture capture;
    if (capture_open(&capture,argv[1])) { fprintf(stderr,"Invalid/unreadable classic Ethernet PCAP\n"); return 1; }
    FILE *out=fopen(argv[2],"wb");
    if (!out) { perror(argv[2]); capture_close(&capture); return 1; }
    Record records[BATCH_SIZE]; Work work[256]; pthread_t threads[256];
    int status=0, finished=0;
    while (!finished && !status) {
        size_t used=0;
        while (used<BATCH_SIZE) {
            unsigned char *packet; const unsigned char *key; size_t length, captured;
            int result=capture_next(&capture,&packet,&captured);
            if (result<=0) { finished=1; if (result<0) { fprintf(stderr,"Truncated/invalid PCAP record\n"); status=1; } break; }
            if (!extract_key(packet,captured,&key,&length)) { free(packet); continue; }
            unsigned char *copy=malloc(length?length:1);
            if (!copy) { free(packet); status=1; break; }
            memcpy(copy,key,length); free(packet); records[used].key=copy; records[used++].length=length;
        }
        size_t workers=(size_t)count<used?(size_t)count:used, launched=0;
        for (size_t i=0;i<workers;++i) {
            work[i]=(Work){records,used,i,workers};
            if (pthread_create(&threads[i],NULL,process,&work[i])) { status=1; break; }
            ++launched;
        }
        for (size_t i=0;i<launched;++i) pthread_join(threads[i],NULL);
        for (size_t i=0;i<used;++i) {
            if (!status) {
                fputs("{\"key\":",out); write_json_key(out,records[i].key,records[i].length);
                fputs(",\"sha1\":\"",out);
                for (size_t j=0;j<SHA_DIGEST_LENGTH;++j) fprintf(out,"%02x",records[i].hash[j]);
                fputs("\"}\n",out);
            }
            free(records[i].key);
        }
    }
    if (ferror(out)) status=1;
    if (fclose(out)) status=1;
    capture_close(&capture);
    return status;
}
