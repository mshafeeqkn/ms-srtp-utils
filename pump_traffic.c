#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <assert.h>
#include <unistd.h>
#include <inttypes.h>

#define     PACKET_COUNT    (1 * 10)      // The packet count may be changed if the pcap having packet loss

static size_t   rtp_offset = 0;
static uint32_t frame_nr = 0;
static struct   timeval start_tv = {0, 0};
static struct   timeval current_tv = {0, 0};
static struct   timeval incr_time = {0, 20000};

struct callback_arg {
    pcap_dumper_t *dumper;
    pcap_t        *pcap;
    uint32_t       packet_count;
    uint16_t       seq_skip_start;
    uint32_t       fr_nr_skip_start;
    uint32_t       skip_count;
};

#ifdef DEBUG_ENABLED
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
#endif

void preproc_pkt(u_char *arg, const struct pcap_pkthdr *hdr, const u_char *bytes) {
    struct callback_arg *cb_data = (struct callback_arg *)arg;
    uint16_t seq_num = ((bytes[0x2C] << 8) | bytes[0x2D]);
    frame_nr++;

    if(seq_num >= cb_data->seq_skip_start) {
        cb_data->fr_nr_skip_start = frame_nr;
        pcap_breakloop(cb_data->pcap);
    }
}


static int skip_count = 0;
void handle_pkt(u_char *arg, const struct pcap_pkthdr *hdr, const u_char *bytes) {
    struct pcap_pkthdr h;
    struct callback_arg *cb_data = (struct callback_arg *)arg;

    frame_nr += 1;

    if (hdr->caplen < rtp_offset) {
        fprintf(stderr, "frame %d dropped: too short\n", frame_nr);
        return;
    }

#ifdef DEBUG_ENABLED
    hexdump(bytes, hdr->caplen - rtp_offset);
#endif

    if (frame_nr == 1) {
        start_tv = hdr->ts;
        current_tv.tv_sec = 0;
        current_tv.tv_usec = 0;
        skip_count = cb_data->skip_count;
    } 

    // Take packets from beginning of the pcap if the we don't have enough packet
    // before skip start.
    uint32_t start_limit = (cb_data->fr_nr_skip_start > cb_data->packet_count) ?
                                cb_data->fr_nr_skip_start - cb_data->packet_count : 0;
    if(frame_nr < start_limit)
        return;

    // Skip the packets from skip start index
    if(frame_nr >= cb_data->fr_nr_skip_start && skip_count) {
        skip_count--;
        return;
    }

    if(frame_nr >= cb_data->fr_nr_skip_start + cb_data->skip_count + cb_data->packet_count)
        return;

    timeradd(&current_tv, &incr_time, &current_tv);
    h.ts.tv_sec = current_tv.tv_sec;
    h.ts.tv_usec = current_tv.tv_usec;
    h.caplen = hdr->caplen;
    h.len = hdr->len;

    pcap_dump((unsigned char*)cb_data->dumper, &h, bytes);
}

void print_help(char *prog_name) {
    printf("\n"
           "Timeshifter v1.0 - Written by Mohammed Shafeeque\n"
           "Command Format:\n"
           "    %s [-b <seq_skip_start>] [-s <skip>] <pcap-file>\n"
           "\n"
           "Description:\n"
           "    This tool is used to rewrite the timestamp to have const delay between\n"
           "    two successive packets in a pcap.\n"
           "\n"
           "    For the pcap having RTP only, some packets can be skipped based on the\n"
           "    sequence number. The pcap constructed after skipping packets will have\n"
           "    the same delay between the packets as mentioned above.\n"
           "\n"
           "Options:\n"
           "    -b num\n"
           "        Beginning of the sequence number. The packet having the sequnce\n"
           "        number 'num' will also be skipped.\n"
           "\n"
           "    -s count\n"
           "        Number of packets to be skipped\n"
           "\n"
           "    -p count\n"
           "        If -b and -s are not specified, the output pcap will have 'count'\n"
           "        number of packets. If they are specified, 'count' number of packets\n"
           "        will be exported before and after the skipped packets.\n"
           "\n", prog_name);
}

pcap_t *get_pcap_offline(char *pcap_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(pcap_name, errbuf);
    struct bpf_program pcap_filter;
    frame_nr = 0;

    if (!pcap) {
        fprintf(stderr, "libpcap failed to open file '%s'\n", errbuf);
        return NULL;
    }
    assert(pcap != NULL);

    if (pcap_compile(pcap, &pcap_filter, "udp", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(pcap, &pcap_filter);
    }

    return pcap;
}

int main(int argc, char *argv[]) {
    pcap_t *pd, *pcap;
    int opt;
    char *pcap_name = NULL;
    struct callback_arg arg = {0};
    char out_file[128] = {0};
    uint32_t packet_count = PACKET_COUNT;
    uint32_t begin_skip = 0;
    uint32_t skip_count = 0;

    while(optind < argc) {
        if((opt = getopt(argc, argv, "p:b:s:h")) != -1) {
            switch(opt) {
                case 'b':
                    begin_skip = atoi(optarg);
                    break;
                case 'p':
                    packet_count = atoi(optarg);
                    break;
                case 's':
                    skip_count = atoi(optarg);
                    break;
                case 'h':
                    print_help(argv[0]);
                    exit(1);
            }
        } else {
            pcap_name = argv[optind];
            optind++;
        }
    }

    if(!pcap_name) {
        print_help(argv[0]);
        return 1;
    }

    // Construct arguments for the callback function
    int file_name_len = strlen(pcap_name);
    strcat(out_file, pcap_name);
    sprintf(out_file + file_name_len - 5, "-out.pcap");

    pd = pcap_open_dead(DLT_EN10MB, 65535);
    arg.dumper          = pcap_dump_open(pd, out_file);
    arg.seq_skip_start  = begin_skip;
    arg.skip_count      = skip_count;
    arg.pcap            = get_pcap_offline(pcap_name);
    arg.packet_count    = packet_count;

    if (rtp_offset == 0) {
        switch(pcap_datalink(arg.pcap)) {
            case DLT_LINUX_SLL:
                rtp_offset = 44;
                break; /* 16 + 20 + 8 */;
            default:
                rtp_offset = 42; /* 14 + 20 + 8 */;
                break;
        }  
    }

    pcap_loop(arg.pcap, 0, preproc_pkt, (u_char*)&arg);
    pcap = get_pcap_offline(pcap_name);
    pcap_loop(pcap, 0, handle_pkt, (u_char*)&arg);
    return 0;
}
