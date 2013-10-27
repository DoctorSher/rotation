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

#endif /* extract.h */

