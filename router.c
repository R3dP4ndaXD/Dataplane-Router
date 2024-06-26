#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "string.h"
#include <arpa/inet.h>
#include <sys/ioctl.h>

/* Routing table */
struct route_table_entry *rtable;
long lengths[33];
int rtable_len;

/* Arp table */
struct arp_table_entry *arp_table;
int arp_table_len; 

struct saved_packet {
	char *buf;
	size_t len;
	struct route_table_entry *best_router;
};

int comp_prefix(uint8_t* prefix1, uint8_t* prefix2) {
	if (prefix1[0] < prefix2[0]) {
		return -1;
	} else if (prefix1[0] > prefix2[0]) {
		return 1;
	} else if (prefix1[1] < prefix2[1]) {
		return -1;
	} else if (prefix1[1] > prefix2[1]) {
		return 1;
	} else if (prefix1[2] < prefix2[2]) {
		return -1;
	} else if (prefix1[2] > prefix2[2]) {
		return 1;
	} else {
		return (int)(prefix1[3] - prefix2[3]);
	}
}
int comp (const void *a, const void *b) {
	struct route_table_entry* entry1 = (struct route_table_entry*)a;
	struct route_table_entry* entry2 = (struct route_table_entry*)b;
	uint8_t* prefix1 = (uint8_t*)&entry1->prefix;
	uint8_t* prefix2 = (uint8_t*)&entry2->prefix;
	if (entry1->mask < entry2->mask) {
		return -1;
	} else if (entry1->mask > entry2->mask) {
		return 1;
	} else {
		return comp_prefix(prefix1, prefix2);
	}
}

/*
 Returns a pointer (eg. &rtable[i]) to the best matching route, or NULL if there
 is no matching route.
*/
struct route_table_entry *get_best_route(uint32_t ip_dest) {
	int l, r;
	int mid;
	struct route_table_entry *res = NULL;
	for (int i = 31; i >= 0; i--) {
		l = lengths[i];
		r = lengths[i + 1] - 1;
		while (l <= r) {
			mid = (l + r) / 2;
			if (rtable[mid].prefix == (ip_dest & rtable[mid].mask)) {
				res = &rtable[mid];
				return res;
			}
			if (comp_prefix((uint8_t*)&rtable[mid].prefix, (uint8_t*)&ip_dest) > 0) {
				r = mid - 1;
			} else {
				l = mid + 1;
			}
		}
	}
	return res;
}

struct route_table_entry *get_best_route_ineficient(uint32_t ip_dest) {
	int lpm_mask = 0;
	struct route_table_entry *lpm = NULL;
	for (int i = 0; i < rtable_len; i++) {
		if (rtable[i].prefix == (ip_dest & rtable[i].mask) && rtable[i].mask > lpm_mask) {		
      		lpm = &rtable[i];
			lpm_mask = rtable[i].mask;
    	}
	}
	return lpm;
}

struct arp_table_entry *get_mac_entry(uint32_t given_ip) {
	//printf("%x given_ip\n",given_ip);
	for (int i = 0; i < arp_table_len; i++) {
		//printf("%x intrarea %i\n",arp_table[i].ip, i);
		if (arp_table[i].ip == given_ip) {
			return &arp_table[i];
		}
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	/* Code to allocate the MAC and route tables */
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	/* DIE is a macro for sanity checks */
	DIE(rtable == NULL, "memory");

	arp_table = malloc(sizeof(struct  arp_table_entry) * 100);
	DIE(arp_table == NULL, "memory");
		
	rtable_len = read_rtable(argv[1], rtable, lengths);
	qsort((void *)rtable, rtable_len, sizeof(struct route_table_entry), comp); 
	//arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	uint8_t interface_mac[6];
	uint8_t broadcast_mac[6];
	hwaddr_aton("ff:ff:ff:ff:ff:ff", broadcast_mac);
	//uint8_t arp_request_mac[6];
	//hwaddr_aton("00:00:00:00:00:00", arp_request_mac);
	queue q = queue_create();
	queue qq = queue_create();
	int count = 0;

	while (1) {
		int interface;
		size_t len;
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		printf("We have received a packet %i\n", count++);
		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		//Validare L2
		get_interface_mac(interface, interface_mac);
		if (strncmp((const char *)(eth_hdr->ether_dhost), (const char *)(broadcast_mac), sizeof(interface_mac)) && strncmp((const char *)(eth_hdr->ether_dhost), (const char *)(interface_mac), sizeof(interface_mac))) {
			printf("pachetul nu are mac dest al meu\n");
			continue;
		}

		if (eth_hdr->ether_type == ntohs(ARPTYPE_IP)) {
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
			struct in_addr port_ip;
			inet_aton (get_interface_ip(interface), &port_ip);
			if (arp_hdr->op == ntohs(ARP_REPLY)) {
				printf("am promit un ARP_REPLY\n");
				if(get_mac_entry(arp_hdr->spa)) {
					printf("exista deja intratea in arp_table!!!!!!\n");
					continue;
				}
				arp_table[arp_table_len].ip = arp_hdr->spa;
				memcpy(&arp_table[arp_table_len].mac, arp_hdr->sha, 6);
				arp_table_len++;
				while(!queue_empty(q)) {
					printf("verifica pachetul din coada\n");
					struct saved_packet* packet = (struct saved_packet*)queue_deq(q);
					struct ether_header *eth_hdr = (struct ether_header *) packet->buf;
					struct arp_table_entry *next_hop = get_mac_entry(packet->best_router->next_hop);
					if (next_hop) {
						memcpy(eth_hdr->ether_dhost, next_hop->mac, 6);
						send_to_link(packet->best_router->interface, packet->buf, packet->len);
						printf("expediez pachetul\n");
						free(packet->buf);
						free(packet);
					} else {
						queue_enq(qq, (void *)packet);
						printf("pachetetul ramane in coada\n");
					}
				}
				queue temp = q;
				q = qq;
				qq = temp;
			} else if (arp_hdr->op == ntohs(ARP_REQUEST) && arp_hdr->tpa == port_ip.s_addr) {
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
				memcpy(arp_hdr->tha, eth_hdr->ether_shost, 6);
				get_interface_mac(interface, eth_hdr->ether_shost);
				memcpy(arp_hdr->sha, eth_hdr->ether_shost, 6);
				arp_hdr->op = htons(ARP_REPLY);
				arp_hdr->tpa = arp_hdr->spa;
				arp_hdr->spa = port_ip.s_addr;
				send_to_link(interface, buf, len);
				printf("am primit ARP_REQUEST si dau reply\n");
			}
		} else if (eth_hdr->ether_type == ntohs(ETHERTYPE_IP)) {
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
			uint32_t recv_sum = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			int sum_ok = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) == recv_sum;
			if (!sum_ok) {
				printf("checksum gresit\n");
				continue;
			}

			struct in_addr port_ip;
			inet_aton(get_interface_ip(interface), &port_ip); ////si celelalte porturi , verifica si type si code
			if (ip_hdr->daddr == port_ip.s_addr) {
				struct icmphdr* icmp_hrd = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
				uint16_t recv_sum = ntohs(icmp_hrd->checksum);
				icmp_hrd->checksum =(uint16_t)0;
				int sum_ok = checksum((uint16_t *)icmp_hrd, sizeof(struct icmphdr)) == recv_sum;
				if (!sum_ok) {
					printf("checksum icmp gresit\n");
					continue;
				}
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
				get_interface_mac(interface, eth_hdr->ether_shost);
				ip_hdr->tos = 0;
				ip_hdr->frag_off = htons(0);
				ip_hdr->version = 4;
				ip_hdr->ihl = 5;
				ip_hdr->id = htons(1);
				ip_hdr->protocol = 1;
				ip_hdr->daddr = ip_hdr->saddr;
				ip_hdr->saddr = port_ip.s_addr;
				icmp_hrd->type = 0;
				icmp_hrd->code = 0;
				icmp_hrd->checksum = htons(checksum((uint16_t *)icmp_hrd, sizeof(struct icmphdr)));
				ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
				send_to_link(interface, buf, len);
				printf("am primit echo request si dau reply\n");
				continue;
			}
			
			if (ip_hdr->ttl <= 1) {
				ip_hdr->check = htons(recv_sum);
				int payload_slice = (64 < len - sizeof(struct ether_header) - sizeof(struct iphdr))? 64 : len - sizeof(struct ether_header) - sizeof(struct iphdr);
				memmove(buf  + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), buf + sizeof(struct ether_header), sizeof(struct iphdr) + payload_slice);
				struct icmphdr* icmp_hrd = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
				get_interface_mac(interface, eth_hdr->ether_shost);
				ip_hdr->tos = 0;
				ip_hdr->frag_off = htons(0);
				ip_hdr->version = 4;
				ip_hdr->ihl = 5;
				ip_hdr->id = htons(1);
				ip_hdr->protocol = 1;
				ip_hdr->daddr = ip_hdr->saddr;
				ip_hdr->saddr = port_ip.s_addr;
				ip_hdr->check = 0;
				ip_hdr->protocol = 1;
				ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) +  sizeof(struct iphdr) + payload_slice);
				ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

				icmp_hrd->type = 11;
				icmp_hrd->code = 0;
				icmp_hrd->checksum = (uint16_t)0;
				icmp_hrd->checksum = htons(checksum((uint16_t *)icmp_hrd, 4));
				
				send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) +  sizeof(struct iphdr) + payload_slice);
				printf("tll <=1 si anunt inapoi\n");
				continue;	
			}
			u_int8_t old_ttl = ip_hdr->ttl;
			ip_hdr->ttl--;
			struct route_table_entry *best_router = get_best_route(ip_hdr->daddr);
			if (!best_router) {
				ip_hdr->check = htons(recv_sum);
				ip_hdr->ttl++;
				int payload_slice = (64 < len - sizeof(struct ether_header) - sizeof(struct iphdr))? 64 : len - sizeof(struct ether_header) - sizeof(struct iphdr);
				memmove(buf  + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), buf + sizeof(struct ether_header), sizeof(struct iphdr) + payload_slice);
				struct icmphdr* icmp_hrd = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
				get_interface_mac(interface, eth_hdr->ether_shost);
				ip_hdr->tos = 0;
				ip_hdr->frag_off = htons(0);
				ip_hdr->version = 4;
				ip_hdr->ihl = 5;
				ip_hdr->id = htons(1);
				ip_hdr->protocol = 1;
				ip_hdr->daddr = ip_hdr->saddr;
				ip_hdr->saddr = port_ip.s_addr;
				ip_hdr->check = (uint16_t)0;
				ip_hdr->protocol = 1;
				ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) +  sizeof(struct iphdr) + payload_slice);
				ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

				icmp_hrd->type = 3;
				icmp_hrd->code = 0;
				icmp_hrd->checksum = (uint16_t)0;
				icmp_hrd->checksum = htons(checksum((uint16_t *)icmp_hrd, 4));
				
				send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) +  sizeof(struct iphdr) + payload_slice);	
				printf("nu am ruta pe care sa trimit pachetul mai departe si anunt senderul\n");
				continue;
			}
			uint32_t old_check = htons(recv_sum);
			ip_hdr->check = ~(~old_check +  ~((uint16_t)old_ttl) + (uint16_t)ip_hdr->ttl) - 1;
			//ip_hdr->protocol = (uint8_t)17;
			//ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
			
			get_interface_mac(best_router->interface, eth_hdr->ether_shost);
			struct arp_table_entry *next_hop = get_mac_entry(best_router->next_hop);
			if (next_hop) {
				memcpy(eth_hdr->ether_dhost, next_hop->mac, 6);
				send_to_link(best_router->interface, buf, len);
				printf("trimit pachetul mai departe(stiu mac next_hop)\n");
			} else {
				struct saved_packet* packet = malloc(sizeof(struct saved_packet));
				packet->buf = calloc(len, sizeof(char));
				packet->len = len;
				packet->best_router = best_router;
				memcpy(packet->buf, buf, len);
				queue_enq(q, (void *)packet);
				
				eth_hdr->ether_type = htons(ARPTYPE_IP);
				memcpy(eth_hdr->ether_dhost, broadcast_mac, 6);
				struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
				arp_hdr->htype = htons(1);
				arp_hdr->ptype = htons(ETHERTYPE_IP);
				arp_hdr->hlen = (uint8_t)6;
				arp_hdr->plen = (uint8_t)4;
				arp_hdr->op = htons(ARP_REQUEST);
				memcpy(arp_hdr->sha, eth_hdr->ether_shost, 6);

				struct in_addr port_ip;
				inet_aton(get_interface_ip(best_router->interface), &port_ip);
				arp_hdr->spa = port_ip.s_addr;
				memcpy(arp_hdr->tha, broadcast_mac, 6);
				arp_hdr->tpa = best_router->next_hop;
				send_to_link(best_router->interface, buf, sizeof(struct ether_header)+ sizeof(struct arp_header));
				printf("nu stiu mac next_hop si dau arp request\n");
			}
		}
	}
}

