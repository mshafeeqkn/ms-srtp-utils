#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <assert.h>
#include <unistd.h>

#include "socket.h"

static size_t rtp_offset = 0;
static int frame_nr = -1;
static struct timeval start_tv = {0, 0};
static struct timeval current_tv = {0, 0};
static struct timeval incr_time = {0, 20000};

struct callback_arg {
    char *src_ip;
    char *dst_ip;
    uint16_t src;
    uint16_t dst;
    int sock;
    pcap_dumper_t *dumper;
};

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
    struct pcap_pkthdr h;
    struct callback_arg *cb_data = (struct callback_arg *)arg;

    frame_nr += 1;

    if (hdr->caplen < rtp_offset) {
        fprintf(stderr, "frame %d dropped: too short\n", frame_nr);
        return;
    }

    memcpy(buffer, bytes + rtp_offset, hdr->caplen - rtp_offset);

    if (frame_nr == 0) {
        start_tv = hdr->ts;
        current_tv.tv_sec = 0;
        current_tv.tv_usec = 0;
    } 

    timeradd(&current_tv, &incr_time, &current_tv);
    h.ts.tv_sec = current_tv.tv_sec;
    h.ts.tv_usec = current_tv.tv_usec;
    h.caplen = hdr->caplen;
    h.len = hdr->len;

    pcap_dump((unsigned char*)cb_data->dumper, &h, bytes);
}

int main(int argc, char *argv[]) {
    pcap_t *pcap, *pd;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program pcap_filter;

    if(argc != 2) {
        fprintf(stderr, "Command Format:\n\n\t%s <pcap-file>", argv[0]);
        return -1;
    }

    int sock = setup_socket();
    struct callback_arg arg = {
        .src_ip = argv[1],
        .dst_ip = argv[2],
        .src = (uint16_t)strtoul(argv[3],  NULL, 10),
        .dst = (uint16_t)strtoul(argv[4],  NULL, 10),
        .sock = sock
    };

    pcap = pcap_open_offline(argv[1], errbuf);
    if (!pcap) {
        fprintf(stderr, "libpcap failed to open file '%s'\n", errbuf);
        exit(1);
    }
    assert(pcap != NULL);

    pd = pcap_open_dead(DLT_EN10MB, 65535);
    arg.dumper = pcap_dump_open(pd, "out.pcap");

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

    pcap_loop(pcap, 0, handle_pkt, (u_char*)&arg);
    return 0;
}
