CC = gcc
CFLAGS = -Wall -Wextra -O2 -I../include
LDFLAGS =

all: carpctl

carpctl: carpctl.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f carpctl

install: carpctl
	install -m 755 carpctl /usr/local/sbin/

.PHONY: all clean install
