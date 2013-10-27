/* IMPORTANT:
 * The output of a signature will be a list of numbers.
 * The list must be the same length regardless of the number of header fields,
 * so we need to allow it to encompass all possible headers.  This is because 
 * libsvm requires fixed sized input.  
 * 
 * Though the list will actually output to stdout in csv format, 
 * we will picture it as a vertical vector.
 *
 * The main part of the output will tell us if the header field was found in 
 * that particular HTTP header, and if so at what index of the header fields?
 * This is because different browsers include different header fields and in
 * different orders.
 * 
 * A 0 designates that the header field was not present in the header. 
 * A 1 through num_fields indicates the order, with 1 being the first field 
 * found in the header and num_fields being the last field found.
 * 
 * |-----|  |--------------------|
 * |  0  |  |       Accept       | 
 * |  2  |  |    Accept-Charset  |
 * |  5  |  |   Accept-Language  |
 * |  0  |  |        Base        |
 * |  0  |  |    Cache-Control   |
 * |  1  |  |  Content-Encoding  |
 * |  3  |  |   Content-Length   |
 * |  0  |  |     Content-MD5    |
 * |  4  |  |     Content-Range  |
 * |  .  |  |          .         |
 * |  .  |  |          .         |
 * |  .  |  |          .         |
 * |-----|  |--------------------|
 *
 * Let it be known that the example is not true to the HTTP Spec,
 * but the program will be.
 *
 * There will be two more numbers in the output.
 * The first is the id value of that particular header.
 * The second is metadata about how many header fields were contained in 
 * that header.
 *
 * The true format of the output is like so:
 * [id],[number of header fields]:[csv]
 *
 * Example:
 * 4,5:0,1,0,1,1,0,0,0,0,4,0,3,0,0,0,2,0,1,...
 */


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

/* Array for header signature */
int order[HTTP_MAX_FIELDS];

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
	/* int i; */
	/* for (i = 0; i < HTTP_MAX_FIELDS; i++) { */
	/* 	fields[i].hdr = 0; */
	/* 	fields[i].idx = 0; */
	/* } */

	/* printf("in zero arr\n"); */
	memset(order, 0, HTTP_MAX_FIELDS * sizeof(int));
}

static void sigify(const char *key, 
				   const char *value, 
				   const void *obj) 
{
	static unsigned int inc = 1;
	unsigned int idx = inc - *(unsigned int *)obj;

	if (strncmp(key, "Accept",
				strlen("Accept")) == 0) 
	{
		/* Needed to move these cases inside.
		 * While they were on the outside, this if statement would be true 
		 * for the rest of them, so it would eat the selection and set an 
		 * incorrect value on a duplicate entry.
		 *
		 * To visualize, test this code on the "Accept-Language" header field.
		 */
		if(strncmp(key, "Accept-Charset", 
				   strlen("Accept-Charset")) == 0) 
		{
			order[ACCEPT_CHARSET] = idx;
		}
		else if(strncmp(key, "Accept-Encoding", 
						strlen("Accept-Encoding")) == 0)
		{
			order[ACCEPT_ENCODING] = idx;
		}
		else if(strncmp(key, "Accept-Language", 
						strlen("Accept-Language")) == 0)
		{
			order[ACCEPT_LANGUAGE] = idx;
		}
		else order[ACCEPT] = idx;
	} 
	else if(strncmp(key, "Allow", 
					strlen("Allow")) == 0)
	{
		order[ALLOW] = idx;
	}
	else if(strncmp(key, "Authorization", 
					strlen("Authorization")) == 0)
	{
		order[AUTHORIZATION] = idx;
	}
	else if(strncmp(key, "Base", 
					strlen("Base")) == 0)
	{
		order[BASE] = idx;
	}
	else if(strncmp(key,"Cache-Control", 
					strlen("Cache-Control")) == 0)
	{
		order[CACHE_CONTROL] = idx;
	}
	else if(strncmp(key,"Connection", 
					strlen("Connection")) == 0)
	{
		order[CONNECTION] = idx;
	}
	else if(strncmp(key,"Content-Encoding", 
					strlen("Content-Encoding")) == 0)
	{
		order[CONTENT_ENCODING] = idx;
	}
	else if(strncmp(key,"Content-Language", 
					strlen("Content-Language")) == 0)
	{
		order[CONTENT_LANGUAGE] = idx;
	}
	else if(strncmp(key,"Content-Length",
					strlen("Content-Length")) == 0)
	{
		order[CONTENT_LENGTH] = idx;
	}
	else if(strncmp(key,"Content-MD5",
					strlen("Content-MD5")) == 0)
	{
		order[CONTENT_MD5] = idx;
	}
	else if(strncmp(key,"Content-Range",
					strlen("Content-Range")) == 0)
	{
		order[CONTENT_RANGE] = idx;
	}
	else if(strncmp(key,"Content-Type",
					strlen("Content-Type")) == 0)
	{
		order[CONTENT_TYPE] = idx;
	}
	else if(strncmp(key,"Content-Version",
					strlen("Content-Version")) == 0)
	{
		order[CONTENT_VERSION] = idx;
	}
	else if(strncmp(key,"Date",
					strlen("Date")) == 0)
	{
		order[DATE] = idx;
	}
	else if(strncmp(key,"Derived-From",
					strlen("Derived-From")) == 0)
	{
		order[DERIVED_FROM] = idx;
	}
	else if(strncmp(key,"Expires",
					strlen("Expires")) == 0)
	{
		order[EXPIRES] = idx;
	}
	else if(strncmp(key,"Forwarded",
					strlen("Forwarded")) == 0)
	{
		order[FORWARDED] = idx;
	}
	else if(strncmp(key,"From",
					strlen("From")) == 0)
	{
		order[FROM] = idx;
	}
	else if(strncmp(key,"Host",
					strlen("Host")) == 0)
	{
		order[HOST] = idx;
	}
	else if(strncmp(key,"If-Modified-Since",
					strlen("If-Modified-Since")) == 0)
	{
		order[IF_MODIFIED_SINCE] = idx;
	}
	else if(strncmp(key,"Keep-Alive",
					strlen("Keep-Alive")) == 0)
	{
		order[KEEP_ALIVE] = idx;
	}
	else if(strncmp(key,"Last-Modified",
					strlen("Last-Modified")) == 0)
	{
		order[LAST_MODIFIED] = idx;
	}
	else if(strncmp(key,"Link",
					strlen("Link")) == 0)
	{
		order[LINK] = idx;
	}
	else if(strncmp(key,"Location",
					strlen("Location")) == 0)
	{
		order[LOCATION] = idx;
	}
	else if(strncmp(key,"MIME-Version",
					strlen("MIME-Version")) == 0)
	{
		order[MIME_VERSION] = idx;
	}
	else if(strncmp(key,"Pragma",
					strlen("Pragma")) == 0)
	{
		order[PRAGMA] = idx;
	}
	else if(strncmp(key,"Proxy-Authenticate",
					strlen("Proxy-Authenticate")) == 0)
	{
		order[PROXY_AUTHENTICATE] = idx;
	}
	else if(strncmp(key,"Proxy-Authorization",
					strlen("Proxy-Authorization")) == 0)
	{
		order[PROXY_AUTHORIZATION] = idx;
	}
	else if(strncmp(key,"Public",
					strlen("Public")) == 0)
	{
		order[PUBLIC] = idx;
	}
	else if(strncmp(key,"Range",
					strlen("Range")) == 0)
	{
		order[RANGE] = idx;
	}
	else if(strncmp(key,"Referer",
					strlen("Referer")) == 0)
	{
		order[REFERER] = idx;
	}
	else if(strncmp(key,"Refresh",
					strlen("Refresh")) == 0)
	{
		order[REFRESH] = idx;
	}
	else if(strncmp(key,"Retry-After",
					strlen("Retry-After")) == 0)
	{
		order[RETRY_AFTER] = idx;
	}
	else if(strncmp(key,"Server",
					strlen("Server")) == 0)
	{
		order[SERVER] = idx;
	}
	else if(strncmp(key,"Title",
					strlen("Title")) == 0)
	{
		order[TITLE] = idx;
	}
	else if(strncmp(key,"Transfer Encoding",
					strlen("Transfer Encoding")) == 0)
	{
		order[TRANSFER_ENCODING] = idx;
	}
	else if(strncmp(key,"Unless",
					strlen("Unless")) == 0)
	{
		order[UNLESS] = idx;
	}
	else if(strncmp(key,"Upgrade",
					strlen("Upgrade")) == 0)
	{
		order[UPGRADE] = idx;
	}
	else if(strncmp(key,"URI",
					strlen("URI")) == 0)
	{
		order[URI] = idx;
	}
	else if(strncmp(key,"User-Agent",
					strlen("User-Agent")) == 0)
	{
		order[USER_AGENT] = idx;
	}
	else if(strncmp(key,"WWW-Authenticate",
					strlen("WWW-Authenticate")) == 0)
	{
		order[WWW_AUTHENTICATE] = idx;
	}
	++inc;
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

		printf("%d,%d:",l->id, l->num);
		sm_enum(l->sm, sigify, &num);
		num += l->num;

		/* Did it exist in the header fields? What index was it at? */
		for (i = 0; i < HTTP_MAX_FIELDS - 1; i++) {
			printf("%d,",order[i]);
		}
		++i;
		printf("%d\n",order[i]);
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
	printf("\n");
	print_stats();
	printf("\n");


	cleanup();

    return 0;
}

