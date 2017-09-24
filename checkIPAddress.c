#include "capture.h"

#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* function that detects specified ip address */
void checkIpAddress(unsigned char *pktData, char *targetAddr)
{

	ip_header *iph = (ip_header *)(&pktData[14]);
	struct sockaddr_in src, dst;

	src.sin_addr.s_addr = iph->srcAddr;
	dst.sin_addr.s_addr = iph->dstAddr;

	char *srcAddr = inet_ntoa(src.sin_addr);
	char *dstAddr = inet_ntoa(dst.sin_addr);

	if( !strcmp(srcAddr, targetAddr) )  printf("###=====>>>> Target address founed in srcAddr [%s]\n", srcAddr);
	else if( !strcmp(dstAddr, targetAddr) )  printf("###=====>>>> Target address founed in dstAddr [%s]\n", dstAddr);


	// argument : (user's input, packet's ip)

	/* function
	 	1. compare user's input & packet's ip
		2. if equal then display & logging it
		3. if not equal just pass
	 */

	return;
}
