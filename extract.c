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

struct field fields[HTTP_MAX_FIELDS];

void add_pair(StrMap *sm, char *buf) {
    char *token, *cmd[100], *val;
    int i = 0;
    int n_bytes = 0;
    int j;

    token = strtok(buf, ": ");
    while (token != NULL) {
        n_bytes += strlen(token);
        cmd[i] = token;
        ++i;
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

	char *literal1 = cmd[0];
	char *literal2 = val;

	sm_put(sm, literal1, literal2);
	
	free(val);
	// sm_put(sm, cmd[0], val);
}

int extract_hline(uint8_t *ptr, char *buf, size_t size) {
    unsigned int i = 0;
    while (*(uint16_t *)ptr != CRLF) {
        if (i == size) return -1;

        buf[i] = *(uint8_t *)ptr;
		++ptr;
		++i;
    }
    buf[i] = '\0';
	++i;
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
        ++ptr;
        ++i;
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
			++ptr;
			++i;
        }

        buf[i] = '\0';
        add_pair(l->sm, buf);

        if (*(uint32_t *)ptr == HF_END) break;
        ptr += 2;
    }

	l->num = num_fields;
    l->ipaddr = ip->daddr;
    l->id = id++;

    HASH_ADD_INT(hmap, id, l);
}

void zero_arr() {
	int i;
	for (i = 0; i < HTTP_MAX_FIELDS; i++) {
		fields[i].hdr = 0;
		fields[i].idx = 0;
	}
}

static void sigify(const char *key, 
				   const char *value, 
				   const void *obj) 
{
	static int idx = 1;
	if (strncmp(key, "Accept",
				strlen("Accept")) == 0) 
	{
		fields[ACCEPT].idx = idx - *(unsigned int *)obj;
		fields[ACCEPT].hdr = 1;
	} 
	else if(strncmp(key, "Accept-Charset", 
					strlen("Accept-Charset")) == 0) 
	{
		fields[ACCEPT_CHARSET].idx = idx - *(unsigned int *)obj;
		fields[ACCEPT_CHARSET].hdr = 1;
	}
	else if(strncmp(key, "Accept-Encoding", 
					strlen("Accept-Encoding")) == 0)
	{
		fields[ACCEPT_ENCODING].idx = idx - *(unsigned int *)obj;
		fields[ACCEPT_ENCODING].hdr = 1;
	}
	else if(strncmp(key, "Accept-Language", 
					strlen("Accept-Language")) == 0)
	{
		fields[ACCEPT_LANGUAGE].idx = idx - *(unsigned int *)obj;
		fields[ACCEPT_LANGUAGE].hdr = 1;
	}
	else if(strncmp(key, "Allow", 
					strlen("Allow")) == 0)
	{
		fields[ALLOW].idx = idx - *(unsigned int *)obj;
		fields[ALLOW].hdr = 1;
	}
	else if(strncmp(key, "Authorization", 
					strlen("Authorization")) == 0)
	{
		fields[AUTHORIZATION].idx = idx - *(unsigned int *)obj;
		fields[AUTHORIZATION].hdr = 1;
	}
	else if(strncmp(key, "Base", 
					strlen("Base")) == 0)
	{
		fields[BASE].idx = idx - *(unsigned int *)obj;
		fields[BASE].hdr = 1;
	}
	else if(strncmp(key,"Cache-Control", 
					strlen("Cache-Control")) == 0)
	{
		fields[CACHE_CONTROL].idx = idx - *(unsigned int *)obj;
		fields[CACHE_CONTROL].hdr = 1;
	}
	else if(strncmp(key,"Connection", 
					strlen("Connection")) == 0)
	{
		fields[CONNECTION].idx = idx - *(unsigned int *)obj;
		fields[CONNECTION].hdr = 1;
	}
	else if(strncmp(key,"Content-Encoding", 
					strlen("Content-Encoding")) == 0)
	{
		fields[CONTENT_ENCODING].idx = idx - *(unsigned int *)obj;
		fields[CONTENT_ENCODING].hdr = 1;
	}
	else if(strncmp(key,"Content-Language", 
					strlen("Content-Language")) == 0)
	{
		fields[CONTENT_LANGUAGE].idx = idx - *(unsigned int *)obj;
		fields[CONTENT_LANGUAGE].hdr = 1;
	}
	else if(strncmp(key,"Content-Length",
					strlen("Content-Length")) == 0)
	{
		fields[CONTENT_LENGTH].idx = idx - *(unsigned int *)obj;
		fields[CONTENT_LENGTH].hdr = 1;
	}
	else if(strncmp(key,"Content-MD5",
					strlen("Content-MD5")) == 0)
	{
		fields[CONTENT_MD5].idx = idx - *(unsigned int *)obj;
		fields[CONTENT_MD5].hdr = 1;
	}
	else if(strncmp(key,"Content-Range",
					strlen("Content-Range")) == 0)
	{
		fields[CONTENT_RANGE].idx = idx - *(unsigned int *)obj;
		fields[CONTENT_RANGE].hdr = 1;
	}
	else if(strncmp(key,"Content-Type",
					strlen("Content-Type")) == 0)
	{
		fields[CONTENT_TYPE].idx = idx - *(unsigned int *)obj;
		fields[CONTENT_TYPE].hdr = 1;
	}
	else if(strncmp(key,"Content-Version",
					strlen("Content-Version")) == 0)
	{
		fields[CONTENT_VERSION].idx = idx - *(unsigned int *)obj;
		fields[CONTENT_VERSION].hdr = 1;
	}
	else if(strncmp(key,"Date",
					strlen("Date")) == 0)
	{
		fields[DATE].idx = idx - *(unsigned int *)obj;
		fields[DATE].hdr = 1;
	}
	else if(strncmp(key,"Derived-From",
					strlen("Derived-From")) == 0)
	{
		fields[DERIVED_FROM].idx = idx - *(unsigned int *)obj;
		fields[DERIVED_FROM].hdr = 1;
	}
	else if(strncmp(key,"Expires",
					strlen("Expires")) == 0)
	{
		fields[EXPIRES].idx = idx - *(unsigned int *)obj;
		fields[EXPIRES].hdr = 1;
	}
	else if(strncmp(key,"Forwarded",
					strlen("Forwarded")) == 0)
	{
		fields[FORWARDED].idx = idx - *(unsigned int *)obj;
		fields[FORWARDED].hdr = 1;
	}
	else if(strncmp(key,"From",
					strlen("From")) == 0)
	{
		fields[FROM].idx = idx - *(unsigned int *)obj;
		fields[FROM].hdr = 1;
	}
	else if(strncmp(key,"Host",
					strlen("Host")) == 0)
	{
		fields[HOST].idx = idx - *(unsigned int *)obj;
		fields[HOST].hdr = 1;
	}
	else if(strncmp(key,"If-Modified-Since",
					strlen("If-Modified-Since")) == 0)
	{
		fields[IF_MODIFIED_SINCE].idx = idx - *(unsigned int *)obj;
		fields[IF_MODIFIED_SINCE].hdr = 1;
	}
	else if(strncmp(key,"Keep-Alive",
					strlen("Keep-Alive")) == 0)
	{
		fields[KEEP_ALIVE].idx = idx - *(unsigned int *)obj;
		fields[KEEP_ALIVE].hdr = 1;
	}
	else if(strncmp(key,"Last-Modified",
					strlen("Last-Modified")) == 0)
	{
		fields[LAST_MODIFIED].idx = idx - *(unsigned int *)obj;
		fields[LAST_MODIFIED].hdr = 1;
	}
	else if(strncmp(key,"Link",
					strlen("Link")) == 0)
	{
		fields[LINK].idx = idx - *(unsigned int *)obj;
		fields[LINK].hdr = 1;
	}
	else if(strncmp(key,"Location",
					strlen("Location")) == 0)
	{
		fields[LOCATION].idx = idx - *(unsigned int *)obj;
		fields[LOCATION].hdr = 1;
	}
	else if(strncmp(key,"MIME-Version",
					strlen("MIME-Version")) == 0)
	{
		fields[MIME_VERSION].idx = idx - *(unsigned int *)obj;
		fields[MIME_VERSION].hdr = 1;
	}
	else if(strncmp(key,"Pragma",
					strlen("Pragma")) == 0)
	{
		fields[PRAGMA].idx = idx - *(unsigned int *)obj;
		fields[PRAGMA].hdr = 1;
	}
	else if(strncmp(key,"Proxy-Authenticate",
					strlen("Proxy-Authenticate")) == 0)
	{
		fields[PROXY_AUTHENTICATE].idx = idx - *(unsigned int *)obj;
		fields[PROXY_AUTHENTICATE].hdr = 1;
	}
	else if(strncmp(key,"Proxy-Authorization",
					strlen("Proxy-Authorization")) == 0)
	{
		fields[PROXY_AUTHORIZATION].idx = idx - *(unsigned int *)obj;
		fields[PROXY_AUTHORIZATION].hdr = 1;
	}
	else if(strncmp(key,"Public",
					strlen("Public")) == 0)
	{
		fields[PUBLIC].idx = idx - *(unsigned int *)obj;
		fields[PUBLIC].hdr = 1;
	}
	else if(strncmp(key,"Range",
					strlen("Range")) == 0)
	{
		fields[RANGE].idx = idx - *(unsigned int *)obj;
		fields[RANGE].hdr = 1;
	}
	else if(strncmp(key,"Referer",
					strlen("Referer")) == 0)
	{
		fields[REFERER].idx = idx - *(unsigned int *)obj;
		fields[REFERER].hdr = 1;
	}
	else if(strncmp(key,"Refresh",
					strlen("Refresh")) == 0)
	{
		fields[REFRESH].idx = idx - *(unsigned int *)obj;
		fields[REFRESH].hdr = 1;
	}
	else if(strncmp(key,"Retry-After",
					strlen("Retry-After")) == 0)
	{
		fields[RETRY_AFTER].idx = idx - *(unsigned int *)obj;
		fields[RETRY_AFTER].hdr = 1;
	}
	else if(strncmp(key,"Server",
					strlen("Server")) == 0)
	{
		fields[SERVER].idx = idx - *(unsigned int *)obj;
		fields[SERVER].hdr = 1;
	}
	else if(strncmp(key,"Title",
					strlen("Title")) == 0)
	{
		fields[TITLE].idx = idx - *(unsigned int *)obj;
		fields[TITLE].hdr = 1;
	}
	else if(strncmp(key,"Transfer Encoding",
					strlen("Transfer Encoding")) == 0)
	{
		fields[TRANSFER_ENCODING].idx = idx - *(unsigned int *)obj;
		fields[TRANSFER_ENCODING].hdr = 1;
	}
	else if(strncmp(key,"Unless",
					strlen("Unless")) == 0)
	{
		fields[UNLESS].idx = idx - *(unsigned int *)obj;
		fields[UNLESS].hdr = 1;
	}
	else if(strncmp(key,"Upgrade",
					strlen("Upgrade")) == 0)
	{
		fields[UPGRADE].idx = idx - *(unsigned int *)obj;
		fields[UPGRADE].hdr = 1;
	}
	else if(strncmp(key,"URI",
					strlen("URI")) == 0)
	{
		fields[URI].idx = idx - *(unsigned int *)obj;
		fields[URI].hdr = 1;
	}
	else if(strncmp(key,"User-Agent",
					strlen("User-Agent")) == 0)
	{
		fields[USER_AGENT].idx = idx - *(unsigned int *)obj;
		fields[USER_AGENT].hdr = 1;
	}
	else if(strncmp(key,"WWW-Authenticate",
					strlen("WWW-Authenticate")) == 0)
	{
		fields[WWW_AUTHENTICATE].idx = idx - *(unsigned int *)obj;
		fields[WWW_AUTHENTICATE].hdr = 1;
	}
	++idx;
}

static void iter(const char *key, 
				 const char *value, 
				 const void *obj) 
{
	printf("\tkey: %s\tvalue: %s\n", key, value);
}

void print_csv() {
    struct label *l;
	unsigned int i, num = 0;
    for (l=hmap; l != NULL; l = l->hh.next) {
		zero_arr();

		printf("%d:",l->id);
		sm_enum(l->sm, sigify, &num);
		num += l->num;

		/* PART 1 - Did it exist in the header fields */
		for (i = 0; i < HTTP_MAX_FIELDS; i++) {
			printf("%d,",fields[i].hdr);
		}
		
		printf("\n");

		/* PART 2 - In what order? */
		for (i = 0; i < HTTP_MAX_FIELDS; i++) {
			printf("%d,",fields[i].idx);
		}

		printf("\n");
		
		/* PART 3 - METADATA */
		printf("%d\n",l->num);

		printf("\n\n");
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

void cleanup() {
	struct label *l, *tmp;

	HASH_ITER(hh, hmap, l, tmp) {
		sm_delete(l->sm);
		HASH_DEL(hmap, l);  
		free(l);  
	}
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

    /* print_hmap(); */
    /* print_stats(); */
	/* printf("\n"); */
	print_csv();

	cleanup();

    return 0;
}

