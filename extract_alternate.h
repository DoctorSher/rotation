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
	int            num;     // number of header fields
    uint32_t       ipaddr;  // the src IP address
    StrMap         *sm;     // associative array for header fields
    UT_hash_handle hh;      // hash handle necessary for UThash
};

struct field {
	int hdr;
	int idx;
};
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


#endif /* extract.h */

