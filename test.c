#include <stdio.h>
#include "checksum.h"


uint8_t data_input[] =  
        {    0x45,0x00,0x00,0x8c,0x28,0xd1,0x00,0x00,0xff,0x06,0x00,0x00,0x73,0xef,0xd2,0x1b,
             0xac,0x15,0x00,0x01,0x00,0x50,0xe7,0xa3,0x93,0x2d,0xac,0xdb,0x9d,0x0e,0x0f,0x41,
             0x50,0x10,0xff,0xff,0x00,0x00,0x00,0x00,0x34,0x70,0x78,0x3b,0x70,0x61,0x64,0x64,
             0x69,0x6e,0x67,0x2d,0x6c,0x65,0x66,0x74,0x3a,0x31,0x30,0x70,0x78,0x3b,0x70,0x61,
             0x64,0x64,0x69,0x6e,0x67,0x2d,0x72,0x69,0x67,0x68,0x74,0x3a,0x31,0x30,0x70,0x78,
             0x3b,0x63,0x75,0x72,0x73,0x6f,0x72,0x3a,0x64,0x65,0x66,0x61,0x75,0x6c,0x74,0x3b,
             0x6f,0x76,0x65,0x72,0x66,0x6c,0x6f,0x77,0x3a,0x68,0x69,0x64,0x64,0x65,0x6e,0x3b,
             0x77,0x68,0x69,0x74,0x65,0x2d,0x73,0x70,0x61,0x63,0x65,0x3a,0x6e,0x6f,0x77,0x72,
             0x61,0x70,0x7d,0x2e,0x63,0x2d,0x64,0x72,0x6f,0x70,0x64,0x6f } ;

uint8_t data_output[] = 
        {    0x45,0x00,0x00,0x8c,0x28,0xd1,0x00,0x00,0xff,0x06,0xa0,0x79,0x73,0xef,0xd2,0x1b,
             0xac,0x15,0x00,0x01,0x00,0x50,0xe7,0xa3,0x93,0x2d,0xac,0xdb,0x9d,0x0e,0x0f,0x41,
             0x50,0x10,0xff,0xff,0xff,0xe6,0x00,0x00,0x34,0x70,0x78,0x3b,0x70,0x61,0x64,0x64,
             0x69,0x6e,0x67,0x2d,0x6c,0x65,0x66,0x74,0x3a,0x31,0x30,0x70,0x78,0x3b,0x70,0x61,
             0x64,0x64,0x69,0x6e,0x67,0x2d,0x72,0x69,0x67,0x68,0x74,0x3a,0x31,0x30,0x70,0x78,
             0x3b,0x63,0x75,0x72,0x73,0x6f,0x72,0x3a,0x64,0x65,0x66,0x61,0x75,0x6c,0x74,0x3b,
             0x6f,0x76,0x65,0x72,0x66,0x6c,0x6f,0x77,0x3a,0x68,0x69,0x64,0x64,0x65,0x6e,0x3b,
             0x77,0x68,0x69,0x74,0x65,0x2d,0x73,0x70,0x61,0x63,0x65,0x3a,0x6e,0x6f,0x77,0x72,
             0x61,0x70,0x7d,0x2e,0x63,0x2d,0x64,0x72,0x6f,0x70,0x64,0x6f };


int main(int argc,char* argv[])
{
    struct Slice data = { 
        .len = sizeof(data_input),
        .data = data_input
    };

    if ( RecomputeChecksum(&data) < 0 ) 
    {
        return -1;
    }

    int n= 0;
    for (; n< data.len ; n++ )
    {
        if ( data_input[n] != data_output[n] )
        {
            printf("check wrong, index=%d\n",n);
            break;
        }
    } 
    if ( n == sizeof(data_input) )
        printf("checksum works well\n");
    return 0;
} 

