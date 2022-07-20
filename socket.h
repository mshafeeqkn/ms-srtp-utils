#ifndef _SOCKET_H_
#define _SOCKET_H_

#include<stdio.h>	//for printf
#include<string.h> //memset
#include<sys/socket.h>	//for socket ofcourse
#include<stdlib.h> //for exit(0);
#include<errno.h> //For errno - the error number
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include<arpa/inet.h>

extern int send_raw_socket(const char *src_ip, const char *dst_ip,
        uint16_t src_port, uint16_t dst_port,
        const unsigned char *data, int data_len, int sock);

extern int setup_socket();

#endif
