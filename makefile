CC = gcc
CFLAGS =
PROGRAMS = extract
LDLIBS = -lpcap

all: ${PROGRAMS}

debug: CFLAGS := ${CFLAGS} -Wall -Wextra -ggdb
debug: ${PROGRAMS}

extract: extract.o strmap.o
	${CC} ${CFLAGS} -o extract extract.o strmap.o ${LDLIBS}

extract.o: extract.c strmap.h uthash.h extract.h
	${CC} ${CFLAGS} -c extract.c

strmap.o: strmap.c strmap.h
	${CC} ${CFLAGS} -c strmap.c

clean:
	rm -f ${PROGRAMS} *.o *~
