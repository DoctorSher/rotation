#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "extract.h"
#include "defs.h"

/* COUNTERS */
int num_ip = 0;
int num_pkts = 0; 
int num_tcp = 0;
int num_gets = 0;
int num_fields = 0;

/* Hash map for header labels */
struct label *hmap = NULL;

void add_pair(StrMap *sm, char *buf) {
    char *token, *cmd[100], *val;
    int i = 0;
    int n_bytes = 0;
    int j;

    token = strtok(buf, ": ");
    while (token != NULL) {
        n_bytes += strlen(token);
        cmd[i] = token;
        i++;
        token = strtok(NULL, " ");
    }
   
    //strtok went overboard, add spaces back
    if (i > 2) {
        val = malloc(n_bytes + i - 2);
        strcpy(val, cmd[1]);
        for (j = 2; j < i; j++) {
            strcat(val, " ");
            strcat(val, cmd[j]);
        }
    } else {
        val = malloc(n_bytes);
        strcpy(val, cmd[1]);
    }

    sm_put(sm, cmd[0], val);
}

int extract_hline(uint8_t *ptr, char *buf, size_t size) {
    unsigned int i = 0;
    while (*(uint16_t *)ptr != CRLF) {
        if (i == size) return -1;

        buf[i] = *(uint8_t *)ptr;
        ptr++;
        i++;
    }
    buf[i] = '\0';
    i++;
    return i;
}

void pkt_search(u_char *args, 
                const struct pcap_pkthdr *pkthdr, 
                const u_char *pkt)
{
    static int id = 0;
    char buf[MAXSIZE];
    int getflag = 0;
    int i;
    uint8_t *ptr, *base;
    struct ether_header *eth;
	struct iphdr *ip;
    struct tcphdr *tcp;

    struct label *l = malloc(sizeof(struct label));

    ptr = (uint8_t *)pkt;
    eth = (struct ether_header *)pkt;
    ++num_pkts;

    // If it's not an IP datagram, we don't care
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    // the offset where ethernet ends and the IP header begins
    ptr += 14;
	ip = (struct iphdr *)ptr;
    ++num_ip;

    // If it's not a TCP segment, we don't care.
    if (ip->protocol != IPPROTO_TCP) return;
    ++num_tcp;

    ptr += (ip->ihl * 4);
    tcp = (struct tcphdr *)ptr;
    
    // If it's not port 80 traffic, we don't care
    if (ntohs(tcp->dest) != 80) return;

    // go to the data offset so we can look for the GET
    ptr += (tcp->doff * 4);

    for (i = 0; i < 8; i++) {
        if (*(uint32_t *)ptr == getlist[i]) {
            getflag = 1;
        }
    }
    
    // If it's not a GET, we don't care. User Agent strings are only in GETs
    if (!getflag) return;
    ++num_gets;

    // consume GET
    i = 0;
    while (*(uint16_t *)ptr != CRLF) {
        buf[i] = *(uint8_t *)ptr;
        ptr++;
        i++;
    }
    ptr += 2;
    buf[i] = '\0';
    // printf("%s",buf);

    // the number of fields that each header will contain
    num_fields = 0;    

    // need to figure out how many fields to allocate for
    base = ptr;
    while (1) {
        while (*(uint16_t *)base != CRLF) {
            base++;
        }
        num_fields++;
        
        if (*(uint32_t *)base == HF_END) break;
        base += 2;
    }

    // start up string mapping
    l->sm = sm_new(num_fields);
    if (l->sm == NULL) {
        fprintf(stderr, "Error creating string map\n");
    }

    while (1) {
        i = 0;
        while (*(uint16_t *)ptr != CRLF) {
            buf[i] = *(uint8_t *)ptr;
            ptr++;
            i++;
        }

        buf[i] = '\0';
        // printf("%s\n",buf);
        add_pair(l->sm, buf);
        num_fields++;

        if (*(uint32_t *)ptr == HF_END) break;
        ptr += 2;
    }

    l->ipaddr = ip->daddr;
    l->id = id++;

    HASH_ADD_INT(hmap, id, l);

    // free(l);
}

static void iter(const char *key, 
				 const char *value, 
				 const void *obj) 
{
	printf("\tkey: %s\tvalue: %s\n", key, value);
}

void print_csv() {
    struct label *l;
    for (l=hmap; l != NULL; l = l->hh.next) {
        printf("****** LABEL %d *******\n",l->id);
        printf("IP Address: %s\n", 
			   inet_ntoa(*(struct in_addr *)&l->ipaddr));
		sm_enum(l->sm, iter, NULL);
        printf("-----------------------\n\n");
    }
}

void print_hmap() {
    struct label *l;
    for (l=hmap; l != NULL; l = l->hh.next) {
        printf("****** LABEL %d *******\n",l->id);
        printf("IP Address: %s\n", 
			   inet_ntoa(*(struct in_addr *)&l->ipaddr));
		sm_enum(l->sm, iter, NULL);
        printf("-----------------------\n\n");
    }
}

void print_stats() {
    printf("Statistics:\n");
    printf("Number of packets processed: %d\n", num_pkts);
    printf("Number of IP datagrams processed: %d\n", num_ip);
    printf("Number of TCP segments processed: %d\n", num_tcp);
    printf("Number of HTTP GET requests processed: %d\n", num_gets);
}

void usage() {
    printf("%s\n","Usage:  extract pcap");
    printf("\t%s\n","<pcap> is a saved packet capture file");
}

int main(int argc, char **argv) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char prestr[80];

    if (argc != 2) {
        usage();
        exit(EXIT_FAILURE);
    }
    
    if ((handle = pcap_open_offline(argv[1], errbuf)) == NULL) {
        perror("pcap_open_offline");
        exit(EXIT_FAILURE);
    }

    if (pcap_loop(handle, 0, pkt_search, NULL) < 0) {
        snprintf(prestr, 80, "Error looping through savefile");
        pcap_perror(handle, prestr);
        exit(EXIT_FAILURE);
    }

    pcap_close(handle);

    print_hmap();
    print_stats();
	printf("\n");

    return 0;
}

