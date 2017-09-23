#pragma once

#include "capture.h"

/********** [LAYER 2] ************/
typedef struct mac_address{
		u_char	addr1;
		u_char	addr2;
		u_char	addr3;
		u_char	addr4;
		u_char	addr5;
		u_char	addr6;
}mac_addr;

typedef struct ethernet_header{
		mac_addr  dstMac; // 6 bytes(e.g. FF:FF:FF:FF:FF:FF)
		mac_addr  srcMac; // 6 bytes(e.g. FF:FF:FF:FF:FF:FF)
		u_short   type;   // When type field is 0x0800, upper layer is IP.
}eth_header;

/********** [LAYER 3] ************/
typedef struct ipv4_header{
		u_char	version:4;      // Only 4 bits used for version field
		u_char  headerLength:4  // Only 4 bits used for header length
		u_char	Tos;	        // Type of Service (TOS)
		u_short	length;	        // Total Length;
		u_short	id;	        // Identification
		u_short	Fragment;       // Fragment offset
		u_char	TTL;	        // Time to live
		u_char	protocol;       // Protocol
		u_short	Hchecksum;      // Header checksum
		u_int	srcAddr;        // Source ip address.
		u_int	dstAddr;        // Destination ip address.
}ip_header;


/********** [LAYER 4] ************/
typedef struct tcp_header{
		u_short		srcPort;// source port nubmer
		u_short		dstPort;// destination port number
		u_int		seqNum; // sequence number
		u_int		ackNum;	// ack number
		u_char		OF_RV;	// left most 4 bits : Offset || right most 4 bits: reserved
		u_char		flag;	// TCP flags ( C E U A P R S F )
		u_short		Window;
		u_short		checkSum;
		u_short		urgPtr;	// urgent Pointer
		u_int		tcpOpt;	// TCP Option
}tcp_header;

typedef struct udp_header{
		u_short		srcPort;
		u_short		dstPort;
		u_short		length;
		u_short		checkSum;
}udp_header;
