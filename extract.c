/* Usage: extract pcap [csv] [out]
 *  <pcap> is the packet capture file to be supplied as input
 *  <csv> is the name of the csv output file created by the program
 *  <out> is the name of the output file for the User-Agent strings
 */

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
 * A 1 indicates that the field exists in the header.
 * 
 * |-----|  |--------------------|
 * |  0  |  |       Accept       | 
 * |  1  |  |    Accept-Charset  |
 * |  1  |  |   Accept-Language  |
 * |  0  |  |        Base        |
 * |  0  |  |    Cache-Control   |
 * |  1  |  |  Content-Encoding  |
 * |  1  |  |   Content-Length   |
 * |  0  |  |     Content-MD5    |
 * |  1  |  |     Content-Range  |
 * |  .  |  |          .         |
 * |  .  |  |          .         |
 * |  .  |  |          .         |
 * |-----|  |--------------------|
 *
 * Let it be known that the example is not true to the HTTP Spec,
 * but the program is.
 *
 * The second part of the output is the same length, and zeros still denote 
 * that the header field did not appear in the current header.  This time,
 * the number 1 is replaced with the number header field it is in reference
 * to defs.h. HOWEVER, THE NUMBER IN THE OUTPUT WILL BE ONE LARGER THAN THE 
 * ACTUAL #DEFINE VALUE IN DEFS.H! Also, the numbers show up in order of 
 * appearance. The output is the same length (they are padded by zeroes) for
 * libsvm purposes. An example is shown below. I suggest opening defs.h for
 * reference.  Note in particular that 2 in the output denotes Accept-Charset,
 * which is a 1 in defs.h.  This is the trickery we are talking about. 
 *
 * |-----|  |--------------------|
 * |  2  |  |    Accept-Charset  |
 * |  43 |  |     User-Agent     |
 * |  10 |  |  Content-Encoding  |
 * |  12 |  |   Content-Length   |
 * |  0  |  |                    |
 * |  0  |  |                    |
 * |  .  |  |                    |
 * |  .  |  |                    |
 * |  .  |  |                    |
 * |-----|  |--------------------|
 *
 * This example means that the headers appeared in the order of:
 * Accept-Charset, User-Agent, Content-Encoding, and Content-Length.
 * No other header fields were included, which we know because the zeros
 * start occuring.
 *
 * Lastly, there is one number at the start of these two csv parts, which
 * represents the number of header fields. It could be easily gleamed from 
 * the csv, but it will be easier to use if it is at the start.
 *
 * So, just to recap, the true format of the output is like so:
 * Size:    1 num                 44 nums            44 nums
 * [number of header fields],[csv for existence],[csv for order]
 *
 * Example:
 * 5:0,1,0,1,1,0,0,0,0,1,0,1,0,0,0,0,...,2,6,14,42,9,0,0,0,0...
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

/* Arrays for header signature */
int exists[HTTP_MAX_FIELDS];
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
        /* The Cookie keyword is not an HTML header field, but 
         * it will be read as one and throw off our count. So,
         * we only add the text if it's NOT the Cookie field,
         * and if it is then we decrement our count by 1 so it
         * is true to the number of HTTP header fields.
         */
        if ((strlen(buf) >= strlen("Cookie")) &&
            (strncmp(buf,"Cookie",strlen("Cookie")) != 0)) {
            add_pair(l->sm, buf);
        } else {
            num_fields--;
        }

        if (*(uint32_t *)ptr == HF_END) break;
        ptr += 2;
    }

    l->num = num_fields;
    l->ipaddr = ip->daddr;
    l->id = id++;

    HASH_ADD_INT(hmap, id, l);
}

static void sigify(const char *key, 
                   const char *value, 
                   const void *obj) 
{
    static unsigned int inc = 0;
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
            exists[ACCEPT_CHARSET] = 1;
            order[idx] = ACCEPT_CHARSET + 1;
        }
        else if(strncmp(key, "Accept-Encoding", 
                        strlen("Accept-Encoding")) == 0)
        {
            exists[ACCEPT_ENCODING] = 1;
            order[idx] = ACCEPT_ENCODING + 1;
        }
        else if(strncmp(key, "Accept-Language", 
                        strlen("Accept-Language")) == 0)
        {
            exists[ACCEPT_LANGUAGE] = 1;
            order[idx] = ACCEPT_LANGUAGE + 1;
        }
        else { 
            exists[ACCEPT] = 1;
            order[idx] = ACCEPT + 1;
        }
    } 
    else if(strncmp(key, "Allow", 
                    strlen("Allow")) == 0)
    {
        exists[ALLOW] = 1;
        order[idx] = ALLOW + 1;
    }
    else if(strncmp(key, "Authorization", 
                    strlen("Authorization")) == 0)
    {
        exists[AUTHORIZATION] = 1;
        order[idx] = AUTHORIZATION + 1;
    }
    else if(strncmp(key, "Base", 
                    strlen("Base")) == 0)
    {
        exists[BASE] = 1;
        order[idx] = BASE + 1;
    }
    else if(strncmp(key,"Cache-Control", 
                    strlen("Cache-Control")) == 0)
    {
        exists[CACHE_CONTROL] = 1;
        order[idx] = CACHE_CONTROL + 1;
    }
    else if(strncmp(key,"Connection", 
                    strlen("Connection")) == 0)
    {
        exists[CONNECTION] = 1;
        order[idx] = CONNECTION + 1;
    }
    else if(strncmp(key,"Content-Encoding", 
                    strlen("Content-Encoding")) == 0)
    {
        exists[CONTENT_ENCODING] = 1;
        order[idx] = CONTENT_ENCODING + 1;
    }
    else if(strncmp(key,"Content-Language", 
                    strlen("Content-Language")) == 0)
    {
        exists[CONTENT_LANGUAGE] = 1;
        order[idx] = CONTENT_LANGUAGE + 1;
    }
    else if(strncmp(key,"Content-Length",
                    strlen("Content-Length")) == 0)
    {
        exists[CONTENT_LENGTH] = 1;
        order[idx] = CONTENT_LENGTH + 1;
    }
    else if(strncmp(key,"Content-MD5",
                    strlen("Content-MD5")) == 0)
    {
        exists[CONTENT_MD5] = 1;
        order[idx] = CONTENT_MD5 + 1;
    }
    else if(strncmp(key,"Content-Range",
                    strlen("Content-Range")) == 0)
    {
        exists[CONTENT_RANGE] = 1;
        order[idx] = CONTENT_RANGE + 1;
    }
    else if(strncmp(key,"Content-Type",
                    strlen("Content-Type")) == 0)
    {
        exists[CONTENT_TYPE] = 1;
        order[idx] = CONTENT_TYPE + 1;
    }
    else if(strncmp(key,"Content-Version",
                    strlen("Content-Version")) == 0)
    {
        exists[CONTENT_VERSION] = 1;
        order[idx] = CONTENT_VERSION + 1;
    }
    else if(strncmp(key,"Date",
                    strlen("Date")) == 0)
    {
        exists[DATE] = 1;
        order[idx] = DATE + 1;
    }
    else if(strncmp(key,"Derived-From",
                    strlen("Derived-From")) == 0)
    {
        exists[DERIVED_FROM] = 1;
        order[idx] = DERIVED_FROM + 1;
    }
    else if(strncmp(key,"Expires",
                    strlen("Expires")) == 0)
    {
        exists[EXPIRES] = 1;
        order[idx] = EXPIRES + 1;
    }
    else if(strncmp(key,"Forwarded",
                    strlen("Forwarded")) == 0)
    {
        exists[FORWARDED] = 1;
        order[idx] = FORWARDED + 1;
    }
    else if(strncmp(key,"From",
                    strlen("From")) == 0)
    {
        exists[FROM] = 1;
        order[idx] = FROM + 1;
    }
    else if(strncmp(key,"Host",
                    strlen("Host")) == 0)
    {
        exists[HOST] = 1;
        order[idx] = HOST + 1;
    }
    else if(strncmp(key,"If-Modified-Since",
                    strlen("If-Modified-Since")) == 0)
    {
        exists[IF_MODIFIED_SINCE] = 1;
        order[idx] = IF_MODIFIED_SINCE + 1;
    }
    else if(strncmp(key,"Keep-Alive",
                    strlen("Keep-Alive")) == 0)
    {
        exists[KEEP_ALIVE] = 1;
        order[idx] = KEEP_ALIVE + 1;
    }
    else if(strncmp(key,"Last-Modified",
                    strlen("Last-Modified")) == 0)
    {
        exists[LAST_MODIFIED] = 1;
        order[idx] = LAST_MODIFIED + 1;
    }
    else if(strncmp(key,"Link",
                    strlen("Link")) == 0)
    {
        exists[LINK] = 1;
        order[idx] = LINK + 1;
    }
    else if(strncmp(key,"Location",
                    strlen("Location")) == 0)
    {
        exists[LOCATION] = 1;
        order[idx] = LOCATION + 1;
    }
    else if(strncmp(key,"MIME-Version",
                    strlen("MIME-Version")) == 0)
    {
        exists[MIME_VERSION] = 1;
        order[idx] = MIME_VERSION + 1;
    }
    else if(strncmp(key,"Pragma",
                    strlen("Pragma")) == 0)
    {
        exists[PRAGMA] = 1;
        order[idx] = PRAGMA + 1;
    }
    else if(strncmp(key,"Proxy-Authenticate",
                    strlen("Proxy-Authenticate")) == 0)
    {
        exists[PROXY_AUTHENTICATE] = 1;
        order[idx] = PROXY_AUTHENTICATE + 1;
    }
    else if(strncmp(key,"Proxy-Authorization",
                    strlen("Proxy-Authorization")) == 0)
    {
        exists[PROXY_AUTHORIZATION] = 1;
        order[idx] = PROXY_AUTHORIZATION + 1;
    }
    else if(strncmp(key,"Public",
                    strlen("Public")) == 0)
    {
        exists[PUBLIC] = 1;
        order[idx] = PUBLIC + 1;
    }
    else if(strncmp(key,"Range",
                    strlen("Range")) == 0)
    {
        exists[RANGE] = 1;
        order[idx] = RANGE + 1;
    }
    else if(strncmp(key,"Referer",
                    strlen("Referer")) == 0)
    {
        exists[REFERER] = 1;
        order[idx] = REFERER + 1;
    }
    else if(strncmp(key,"Refresh",
                    strlen("Refresh")) == 0)
    {
        exists[REFRESH] = 1;
        order[idx] = REFRESH + 1;
    }
    else if(strncmp(key,"Retry-After",
                    strlen("Retry-After")) == 0)
    {
        exists[RETRY_AFTER] = 1;
        order[idx] = RETRY_AFTER + 1;
    }
    else if(strncmp(key,"Server",
                    strlen("Server")) == 0)
    {
        exists[SERVER] = 1;
        order[idx] = SERVER + 1;
    }
    else if(strncmp(key,"Title",
                    strlen("Title")) == 0)
    {
        exists[TITLE] = 1;
        order[idx] = TITLE + 1;
    }
    else if(strncmp(key,"Transfer Encoding",
                    strlen("Transfer Encoding")) == 0)
    {
        exists[TRANSFER_ENCODING] = 1;
        order[idx] = TRANSFER_ENCODING + 1;
    }
    else if(strncmp(key,"Unless",
                    strlen("Unless")) == 0)
    {
        exists[UNLESS] = 1;
        order[idx] = UNLESS + 1;
    }
    else if(strncmp(key,"Upgrade",
                    strlen("Upgrade")) == 0)
    {
        exists[UPGRADE] = 1;
        order[idx] = UPGRADE + 1;
    }
    else if(strncmp(key,"URI",
                    strlen("URI")) == 0)
    {
        exists[URI] = 1;
        order[idx] = URI + 1;
    }
    else if(strncmp(key,"User-Agent",
                    strlen("User-Agent")) == 0)
    {
        exists[USER_AGENT] = 1;
        order[idx] = USER_AGENT + 1;
    }
    else if(strncmp(key,"WWW-Authenticate",
                    strlen("WWW-Authenticate")) == 0)
    {
        exists[WWW_AUTHENTICATE] = 1;
        order[idx] = WWW_AUTHENTICATE + 1;
    }
    ++inc;
}

static void iter(const char *key, 
                 const char *value, 
                 const void *obj) 
{
    printf("\tkey: %s\tvalue: %s\n", key, value);
}

void write_files(char *c, char *o) {
    struct label *l;
    unsigned int i, num = 0;
    char buf[1000]; // note that this limits the UA to 1000 chars

    
    FILE *csv = fopen(c, "w");
    if (csv == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    FILE *out = fopen(o, "w");
    if (out == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }


    for (l=hmap; l != NULL; l = l->hh.next) {
        /* zero the arrays to clear the last iteration */
        memset(exists, 0, HTTP_MAX_FIELDS * sizeof(int));
        memset(order, 0, HTTP_MAX_FIELDS * sizeof(int));

        fprintf(csv, "%d,", l->num);
        sm_enum(l->sm, sigify, &num);
        num += l->num;

        /* Did it exist in the header fields? */
        for (i = 0; i < HTTP_MAX_FIELDS; i++) {
            fprintf(csv, "%d,",exists[i]);
        }
        /* What order did they show up in? */
        for (i = 0; i < HTTP_MAX_FIELDS - 1; i++) {
            fprintf(csv, "%d,",order[i]);
        }
        ++i;
        fprintf(csv, "%d\n",order[i]);

        if (sm_get(l->sm, "User-Agent", buf, sizeof(buf)) != 0) {
            fprintf(out, "%s\n", buf);
        } else {
            fprintf(out, "%s\n", "User-Agent string was not found in the header fields");
        }
    }

    if (fclose(csv) != 0) {
        perror("fclose");
        exit(EXIT_FAILURE);
    }

    if (fclose(out) != 0) {
        perror("fclose");
        exit(EXIT_FAILURE);
    }
}

void print_csv() {
    struct label *l;
    unsigned int i, num = 0;
    for (l=hmap; l != NULL; l = l->hh.next) {
        /* zero the arrays to clear the last iteration */
        memset(exists, 0, HTTP_MAX_FIELDS * sizeof(int));
        memset(order, 0, HTTP_MAX_FIELDS * sizeof(int));

        printf("%d,", l->num);
        sm_enum(l->sm, sigify, &num);
        num += l->num;

        /* Did it exist in the header fields? */
        for (i = 0; i < HTTP_MAX_FIELDS; i++) {
            printf("%d,",exists[i]);
        }
        /* What order did they show up in? */
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
    printf("%s\n","Usage: extract pcap [csv] [out]");
    printf("\t%s\n","<pcap> is a saved packet capture file");
    printf("\t%s\n","<csv> is the name of the output file containing the CSV HTTP signatures");
    printf("\t%s\n","<out> is the name of the output file containing the User-Agent strings");
}

int main(int argc, char **argv) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char prestr[80];
    char out[100], csv[100];

    memset(out, 0, 100);
    memset(csv, 0, 100);    

    if (argc < 2 || argc > 4) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (argc > 2) {
        strncpy(csv, argv[2], strlen(argv[2]));
        if (argc == 4) {
            strncpy(out, argv[3], strlen(argv[3]));
        } else {
            strncpy(out, "user_agent", strlen("user_agent"));
        }
    } else {
        strncpy(csv, "http_sigs", strlen("http_sigs"));
        strncpy(out, "user_agent", strlen("user_agent"));
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

    write_files(csv, out);
    print_stats();

    cleanup();

    return 0;
}

