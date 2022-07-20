#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <assert.h>

#include "socket.h"

static size_t rtp_offset = 0;
static int frame_nr = -1;
static struct timeval start_tv = {0, 0};

void hexdump(const void *ptr, size_t size) {
    size_t i, j;
    const unsigned char *cptr = (unsigned char *)ptr;

    for (i = 0; i < size; i += 16) {
        printf("%04x  ", (int)i);
        for (j = 0; j < 16 && i+j < size; j++) {
            printf("%02x ", cptr[i+j]);
            if(j == 7)
                printf(" ");
        }
        printf("\n");
    }
}

void handle_pkt(u_char *arg, const struct pcap_pkthdr *hdr, const u_char *bytes) {
    unsigned char buffer[2048];
    size_t pktsize;
    struct timeval delta;
    int sock = (int)*arg;

    frame_nr += 1;

    if (hdr->caplen < rtp_offset) {
        fprintf(stderr, "frame %d dropped: too short\n", frame_nr);
        return;
    }

    memcpy(buffer, bytes + rtp_offset, hdr->caplen - rtp_offset);
    pktsize = hdr->caplen - rtp_offset;

    if (frame_nr == 0) {
        start_tv = hdr->ts;
    } 

    timersub(&hdr->ts, &start_tv, &delta);
    printf("%02ld:%02ld.%06lu       [len: %d]\n", delta.tv_sec/60, delta.tv_sec%60, delta.tv_usec, hdr->caplen);

    // hexdump(bytes, hdr->caplen);
    hexdump(buffer, pktsize);

    send_raw_socket("1.1.1.137", "1.1.1.56", 5060, 5060, buffer, pktsize, sock);
    if(frame_nr == 5)
        exit(1);
}

int main(int argc, char *argv[]) {
#if 1
    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program pcap_filter;
    int sock = setup_socket();

    pcap = pcap_open_offline("srtp_srtcp.pcap", errbuf);
    if (!pcap) {
        fprintf(stderr, "libpcap failed to open file '%s'\n", errbuf);
        exit(1);
    }
    assert(pcap != NULL);

    // We are only interested in udp traffic
    if (pcap_compile(pcap, &pcap_filter, "udp", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(pcap, &pcap_filter);
    }

    if (rtp_offset == 0) {
        switch(pcap_datalink(pcap)) {
            case DLT_LINUX_SLL:
                rtp_offset = 44;
                break; /* 16 + 20 + 8 */;
            default:
                rtp_offset = 42; /* 14 + 20 + 8 */;
                break;
        }  
    }

    pcap_loop(pcap, 0, handle_pkt, (u_char*)&sock);
#else
    test_raw_socket();
#endif
}
