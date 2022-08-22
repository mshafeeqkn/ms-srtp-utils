#include "socket.h"
/*
	96 bit (12 bytes) pseudo header needed for udp header checksum calculation
*/
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
};

/*
	Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;

	return(answer);
}

int setup_socket() {
	//Create a raw socket of type IPPROTO
	int s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);

	if(s == -1)
	{
		//socket creation failed, may be because of non-root privileges
		perror("Failed to create raw socket");
        return -1;
	}

    return s;
}

int setup_ip_header(const char *src_ip, const char *dst_ip, char *datagram,
        struct pseudo_header *psh, int data_len, struct sockaddr_in *sin) {
    struct iphdr *iph = (struct iphdr *) datagram;
    static int pkt_id = 57853;

	//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + data_len;
	iph->id = htonl(pkt_id++);	//Id of this packet
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr = inet_addr (src_ip);	//Spoof the source ip address
	iph->daddr = sin->sin_addr.s_addr;

	//Ip checksum
	iph->check = csum ((unsigned short *) datagram, iph->tot_len);

	psh->source_address = inet_addr( src_ip );
	psh->dest_address = sin->sin_addr.s_addr;

    return 0;
}

int setup_udp_header(uint16_t src, uint16_t dst, char *datagram, struct pseudo_header *psh) {
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));

	//UDP header
	udph->source = htons (src);
	udph->dest = htons (dst);
	udph->check = 0;	//leave checksum 0 now, filled later by pseudo header

	psh->protocol = IPPROTO_UDP;

    return 0;
}

void calculate_udp_checksum(int data_len, char *datagram, struct pseudo_header *psh) {
    char *pseudo_gram;
    int pseudo_hdr_size;
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));

	psh->udp_length = htons(sizeof(struct udphdr) + data_len );

    pseudo_hdr_size = sizeof(struct pseudo_header) + sizeof(struct udphdr) + data_len;
    pseudo_gram = (char *)malloc(pseudo_hdr_size);

	udph->len = htons(8 + data_len);
    memcpy(pseudo_gram, (char *)psh, sizeof(struct pseudo_header));
    memcpy(pseudo_gram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr) + data_len);
	udph->check = csum( (unsigned short*) pseudo_gram , pseudo_hdr_size);
    free(pseudo_gram);
}

int send_raw_socket(const char *src_ip, const char *dst_ip,
        uint16_t src_port, uint16_t dst_port,
        const unsigned char *data, int data_len, int sock) {
    char datagram[4096] = {0};
    struct pseudo_header psh = {0};
    struct iphdr *iph = (struct iphdr *) datagram;
	struct sockaddr_in sin;
    char *data_ptr;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(80);
	sin.sin_addr.s_addr = inet_addr (dst_ip);

    data_ptr = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
    memcpy(data_ptr, data, data_len);

    setup_ip_header(src_ip, dst_ip, datagram, &psh, data_len, &sin);
    setup_udp_header(src_port, dst_port, datagram, &psh);
    calculate_udp_checksum(data_len, datagram, &psh);

    if (sendto (sock, datagram, iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0) {
        perror("sendto failed");
    }
    return 1;
}
