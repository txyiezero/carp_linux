CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS =

OBJS = carpd.o carpd_netlink.o carpd_cmd.o carpd_daemon.o

all: carpd

carpd: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c carpd.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f carpd $(OBJS)

install: carpd
	install -m 755 carpd /usr/local/sbin/

.PHONY: all clean install
