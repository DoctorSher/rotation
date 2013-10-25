#ifndef EXTRACT_H
#define EXTRACT_H

#include "uthash.h"
#include "strmap.h"

#define MAXSIZE 1000

// double CRLF
#define HF_END 168626701
// single
#define CRLF 2573

// every possible spelling of "GET" 
uint32_t getlist[8] = { 544499047, 542401895, 544490855, 542393703, 544499015, 542401863, 544490823, 542393671};

// Every possible valid 4 byte spelling of "User" 
uint32_t ualist[16] = { 1919251317, 1382380405, 1917154165, 1380283253, 1919243125, 1382372213, 1917145973, 1380275061, 1919251285, 1382380373, 1917154133, 1380283221, 1919243093, 1382372181, 1917145941, 1380275029};

struct label {
    int            id;      // each labels unique ID
    uint32_t       ipaddr;  // the src IP address
    StrMap         *sm;     // associative array for header fields
    UT_hash_handle hh;      // hash handle necessary for UThash
};

struct field {
	int hdr;
	int idx;
}
/* IMPORTANT:
 * The output of a signature will be a list of numbers.
 * The list must be the same length regardless of the number of header fields,
 * so we need to allow it to encompass all possible headers.  This is because 
 * libsvm requires fixed sized input.  
 * 
 * This list has three conceptual parts.  Though the list will actually output
 * to stdout in csv format, we will picture it as a vertical vector.
 *
 * PART 1)
 * Suppose a packet has "keep-alive" as the header field instead of "Keep-Alive".
 * Acknowledging this difference will help us differentiate signatures.
 * As a result, the first part of the output can be seen as the following: 
 *
 * |-----|  |--------------|
 * |  0  |  |  keep-alive  |
 * |  1  |  |  Keep-Alive  |
 * |  0  |  |  KEEP-ALIVE  |
 * |-----|  |--------------|
 *
 * From this example, we can see that this particular HTTP GET used the 
 * "Keep-Alive" header field as opposed to the alternatives.
 * This distinction occurs for all header fields.
 *
 * PART 2)
 * The second part of the output will be the order the header fields appeared.
 * Because the spelling quirks do not matter for this, we only need a
 * representative of the group.  This will likely involve tolower().
 *
 * A 0 designates that the header field was not present in the header. Yes, this
 * seems redundant, but remember libsvm requires us to have one fixed length for
 * all different types of headers.  A 1 through num_fields indicates the order,
 * with 1 being the first field and num_fields being the last.
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
 * PART 3)
 * This is simply a few sports for metadata about the header, which could
 * crop up later.  One that immediately comes to mind is storing the number of 
 * header fields.
 *
 *
 * Remember, the output will actually be in the format of:
 * 0,1,0,1,1,0,0,0,0,4,0,3,0,0,0,2,0,1,.... 
 */

/* 10.9.1 PERSISTENT CONNECTIONS */

#define ACCEPT 0
#define ACCEPT_CHARSET 1
#define ACCEPT_ENCODING 2
#define ACCEPT_LANGUAGE 3
#define ALLOW 4
#define AUTHORIZATION 5
#define BASE 6
#define CACHE_CONTROL 7
#define CONNECTION 8
#define CONTENT_ENCODING 9
#define CONTENT_LANGUAGE 10
#define CONTENT_LENGTH 11
#define CONTENT_MD5 12
#define CONTENT_RANGE 13
#define CONTENT_TYPE 14
#define CONTENT_VERSION 15
#define DATE 16
#define DERIVED_FROM 17
#define EXPIRES 18
#define FORWARDED 19
#define FROM 20
#define HOST 21
#define IF_MODIFIED_SINCE 22
#define KEEP_ALIVE 23
#define LAST_MODIFIED 24
#define LINK 25
#define LOCATION 26
#define MIME_VERSION 27
#define PRAGMA 28
#define PROXY_AUTHENTICATE 29
#define PROXY_AUTHORIZATION 30
#define PUBLIC 31
#define RANGE 32
#define REFERER 33
#define REFRESH 34
#define RETRY_AFTER 35
#define SERVER 36
#define TITLE 37
#define TRANSFER_ENCODING 38
#define UNLESS 39
#define UPGRADE 40
#define URI 41
#define USER_AGENT 42
#define WWW_AUTHENTICATE 43

#define HTTP_MAX_FIELDS 44

 /* ACCEPT */
 /* ACCEPT_CHARSET */
 /* ACCEPT_ENCODING */
 /* ACCEPT_LANGUAGE */
 /* ALLOW */
 /* AUTHORIZATION */
 /* BASE */
 /* CACHE_CONTROL */
 /* CONNECTION */
 /* CONTENT_ENCODING */
 /* CONTENT_LANGUAGE */
 /* CONTENT_LENGTH */
 /* CONTENT_MD5 */
 /* CONTENT_RANGE */
 /* CONTENT_TYPE */
 /* CONTENT_VERSION */
 /* DATE */
 /* DERIVED_FROM */
 /* EXPIRES */
 /* FORWARDED */
 /* FROM */
 /* HOST */
 /* IF_MODIFIED_SINCE */
 /* KEEP_ALIVE */
 /* LAST_MODIFIED */
 /* LINK */
 /* LOCATION */
 /* MIME_VERSION */
 /* PRAGMA */
 /* PROXY_AUTHENTICATE */
 /* PROXY_AUTHORIZATION */
 /* PUBLIC */
 /* RANGE */
 /* REFERER */
 /* REFRESH */
 /* RETRY_AFTER */
 /* SERVER */
 /* TITLE */
 /* TRANSFER_ENCODING */
 /* UNLESS */
 /* UPGRADE */
 /* URI */
 /* USER_AGENT */
 /* WWW_AUTHENTICATE */


/* #define Accept  */
/* #define Accept_Charset */
/* #define Accept_Encoding */
/* #define Accept_Language */
/* #define Allow */
/* #define Authorization */
/* #define Base */
/* #define Cache_Control */
/* #define Connection */
/* /\* 10.9.1 Persistent Connections *\/ */
/* #define Content_Encoding */
/* #define Content_Language */
/* #define Content_Length */
/* #define Content_MD5 */
/* #define Content_Range */
/* #define Content_Type */
/* #define Content_Version */
/* #define Date */
/* #define Derived_From */
/* #define Expires */
/* #define Forwarded */
/* #define From */
/* #define Host */
/* #define If_Modified_Since */
/* #define Keep_Alive */
/* #define Last_Modified */
/* #define Link */
/* #define Location */
/* #define MIME_Version */
/* #define Pragma */
/* #define Proxy_Authenticate */
/* #define Proxy_Authorization */
/* #define Public */
/* #define Range */
/* #define Referer */
/* #define Refresh */
/* #define Retry_After */
/* #define Server */
/* #define Title */
/* #define Transfer_Encoding */
/* #define Unless */
/* #define Upgrade */
/* #define URI */
/* #define User_Agent */
/* #define WWW_Authenticate */


#endif /* EXTRACT_H */

