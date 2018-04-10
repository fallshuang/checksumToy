#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdint.h>


typedef struct Slice{
    unsigned int len;
    unsigned char* data;
} Slice;

extern int RecomputeChecksum(struct Slice *input);

