/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * carpd - CARP daemon for Linux
 * Common header for all source files.
 */
#ifndef _CARPD_H
#define _CARPD_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <sys/stat.h>
#include <signal.h>

/* CARP protocol definitions (shared with kernel module) */
#include "../include/carp.h"

/* Netlink message buffer */
struct nl_msg_buf {
	struct nlmsghdr nlh;
	struct genlmsghdr gnlh;
	char buf[4096];
};

/* ---- Netlink helpers (carpd_netlink.c) ---- */
extern int nl_fd;
extern __u32 nl_seq;

int nl_send_recv(struct nl_msg_buf *req, struct nl_msg_buf *resp);
int find_genl_family(const char *name);
int nlmsg_attr_put(struct nl_msg_buf *msg, int type, int len, const void *data);
int nlmsg_attr_put_u32(struct nl_msg_buf *msg, int type, __u32 val);
int nlmsg_attr_put_s32(struct nl_msg_buf *msg, int type, __s32 val);
int nlmsg_attr_put_string(struct nl_msg_buf *msg, int type, const char *str);
int query_vip(const char *devname, int vhid,
	      char *addr4, size_t addr4_len,
	      char *addr6, size_t addr6_len);

/* ---- Commands (carpd_cmd.c) ---- */
int cmd_add(const char *devname, int vhid, int advbase, int advskew,
	    const char *password, const char *addr, const char *addr6);
int cmd_del(const char *devname, int vhid);
int cmd_set(const char *devname, int vhid, int advbase, int advskew,
	    const char *password, int state, const char *addr,
	    const char *addr6);
int cmd_status(const char *devname, int vhid);

/* ---- Daemon (carpd_daemon.c) ---- */
void manage_address(const char *devname, int vhid,
		    const char *vip, int is_add);
void handle_uevent(const char *envp);
int cmd_daemon(void);

/* ---- Main (carpd.c) ---- */
void usage(const char *prog);

#endif /* _CARPD_H */
