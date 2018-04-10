#include <stdio.h>
#include <assert.h>
#include "checksum.h"

struct tcp_header
{
    uint16_t th_sport;    
    uint16_t th_dport;  
    uint32_t th_seq;      
    uint32_t th_ack; 
    uint8_t th_x2:4;      
    uint8_t th_off:4;     
    uint8_t th_flags;
    uint16_t th_win;      
    uint16_t th_sum;      
    uint16_t th_urp;      
};


static int _set_ip_checksum(struct Slice *input) 
{
    struct ip *this_iphdr = (struct ip*)(input->data);
    uint32_t sum = 0;
    unsigned int i = 0;

    assert(ntohs(this_iphdr->ip_len) == input->len);
    assert(4*this_iphdr->ip_hl <= ntohs(this_iphdr->ip_len));

    if ( this_iphdr->ip_v != 4 )
    {
        fprintf(stderr, "only support ipv4\n");
        return -1;
    } 

    if ( this_iphdr->ip_p != IPPROTO_TCP ) 
    {
        fprintf(stderr, "only support tcp packet\n");
        return -1;
    }

    for (i = 0 ; i < 4*this_iphdr->ip_hl; i += 2 )
    {
        sum += *(uint16_t*)((char *)(this_iphdr) + i) ;
    }

    while (sum >> 16) 
        sum = (sum & 0xFFFF)+(sum >> 16);

    this_iphdr->ip_sum = ~sum  ;
    
    return 0;
}

static inline uint64_t handle_tail(uint64_t sum64, uint8_t* buf, int len)
{
    if ( len & 4 )
    {
        uint32_t s = *(uint32_t*)buf;
        sum64 += s;
        if (sum64 < s) 
            sum64++;
        buf += 4;
    }

    if (len & 2)
    {
        uint16_t s = *(uint16_t *) buf;
        sum64 += s;
        if (sum64 < s) 
            sum64++;
        buf += 2;
    }

    if (len & 1)
    {
        uint8_t s = *(uint8_t *) buf;
        sum64 += s;
        if (sum64 < s) 
            sum64++;
    }

    return sum64;
}

static int _set_tcp_checksum(struct Slice *input) 
{
    struct ip *this_iphdr = (struct ip*)(input->data);
    struct tcp_header *this_tcphdr = (struct tcp_header *)( input->data + 4 * this_iphdr->ip_hl);
    int tcp_packet_size = ntohs(this_iphdr->ip_len) - 4 * this_iphdr->ip_hl ;
    int i = 0;

    assert( this_iphdr->ip_hl*4 + tcp_packet_size == input->len );
  
    //compute the psuedo sum first
    struct psuedo_header
    {
      uint32_t saddr;
      uint32_t daddr;
      uint8_t zero;
      uint8_t protocol;
      uint16_t len;
    } hdr = {
        .saddr = this_iphdr->ip_src.s_addr,
        .daddr = this_iphdr->ip_dst.s_addr,
        .zero = 0,
        .protocol = IPPROTO_TCP,
        .len = htons(tcp_packet_size)
    };
   
#if ! __x86_64__
    uint8_t* buf = (uint8_t*)this_tcphdr;
    uint32_t sum = 0;

    for (i = 0; i < sizeof(hdr); i += 2)
      sum += *(uint16_t*)((uint8_t*)(&hdr) + i) ;
    for (i = 0; i < tcp_packet_size - 1; i += 2)
    {
        sum += *(uint16_t *) &buf[i];
    }

    // pad last byte 
    if (tcp_packet_size & 1)
    {
        sum += (uint8_t)buf[i];
    }

    while (sum >> 16) 
        sum = (sum & 0xFFFF)+(sum >> 16);

    this_tcphdr->th_sum = ~sum;

#else
    uint64_t *p_tcpbuf = NULL;
    uint64_t sum64 = 0;

    // 8 bytes at a time , fast in 64-bit machine
    p_tcpbuf = (uint64_t*)(&hdr);
    for ( i = sizeof(hdr); i>= sizeof(uint64_t); p_tcpbuf++)
    {
        uint64_t s = *p_tcpbuf;
        sum64 += s;
        if (sum64 < s) 
            sum64++;
        i -= sizeof(uint64_t);
    }
    sum64 = handle_tail(sum64, (uint8_t*)p_tcpbuf, i );

    p_tcpbuf = (uint64_t *)this_tcphdr ;
    for (i = tcp_packet_size; i >= sizeof(uint64_t); p_tcpbuf++)
    {
        uint64_t s = *p_tcpbuf;
        sum64 += s;
        if (sum64 < s) 
            sum64++;
        i -= sizeof(uint64_t);
    }
    
    sum64 = handle_tail(sum64, (uint8_t*)p_tcpbuf, i );   

    // fold down to 16 bits 
    uint32_t t1, t2;
    uint16_t t3, t4;
    t1 = sum64; 
    t2 = (sum64 >> 32);
    t1 += t2;
    if (t1 < t2) t1++;
    t3 = t1;
    t4 = t1 >> 16;
    t3 += t4;
    if (t3 < t4) t3++;
    
    this_tcphdr->th_sum = ~t3;
#endif
}

int RecomputeChecksum(struct Slice *input)
{
    assert( input != NULL && input->len > 0 && input->data != NULL );

    if ( _set_ip_checksum(input) < 0 ) return -1;
    if ( _set_tcp_checksum(input) < 0 ) return -1;
    return 0;
}
