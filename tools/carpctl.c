// SPDX-License-Identifier: BSD-2-Clause
/*
 * carpctl - Userspace CARP management tool for Linux
 * Communicates with the CARP kernel module via Generic Netlink.
 *
 * Usage:
 *   carpctl add <dev> <vhid> [options]
 *   carpctl del <dev> <vhid>
 *   carpctl status [<dev> [<vhid>]]
 *   carpctl set <dev> <vhid> [options]
 */

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

/* Netlink definitions matching kernel module */
#define CARP_NL_FAMILY_NAME	"carp"

enum {
	CARP_NL_CMD_UNSPEC = 0,
	CARP_NL_CMD_GET    = 1,
	CARP_NL_CMD_SET    = 2,
};

enum carp_nl_type {
	CARP_NL_UNSPEC  = 0,
	CARP_NL_VHID    = 1,
	CARP_NL_STATE   = 2,
	CARP_NL_ADVBASE = 3,
	CARP_NL_ADVSKEW = 4,
	CARP_NL_KEY     = 5,
	CARP_NL_IFINDEX = 6,
	CARP_NL_ADDR    = 7,
	CARP_NL_ADDR6   = 8,
	CARP_NL_IFNAME  = 9,
};

#define CARP_MAXVHID	255
#define CARP_KEY_LEN	20

static int nl_fd;
static __u32 nl_seq;

/* ---- Netlink helpers ---- */

struct nl_msg_buf {
	struct nlmsghdr nlh;
	struct genlmsghdr gnlh;
	char buf[4096];
};

static int nl_send_recv(struct nl_msg_buf *req, struct nl_msg_buf *resp)
{
	socklen_t len = sizeof(*resp);

	if (send(nl_fd, req, req->nlh.nlmsg_len, 0) < 0)
		return -errno;

	resp->nlh.nlmsg_len = sizeof(*resp);
	if (recv(nl_fd, resp, len, 0) < 0)
		return -errno;

	if (resp->nlh.nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (void *)(resp + 1);
		return err->error;
	}
	return 0;
}

static int nlmsg_attr_put(struct nl_msg_buf *msg, int type, int len, const void *data)
{
	struct nlattr *nla;
	int total = NLA_ALIGN(sizeof(*nla) + len);

	if (msg->nlh.nlmsg_len + total > sizeof(msg->buf))
		return -ENOMEM;

	nla = (struct nlattr *)((char *)msg + msg->nlh.nlmsg_len);
	nla->nla_type = type;
	nla->nla_len = sizeof(*nla) + len;
	memcpy((char *)nla + sizeof(*nla), data, len);
	msg->nlh.nlmsg_len += total;
	return 0;
}

static int nlmsg_attr_put_u32(struct nl_msg_buf *msg, int type, __u32 val)
{
	return nlmsg_attr_put(msg, type, sizeof(val), &val);
}

static int nlmsg_attr_put_s32(struct nl_msg_buf *msg, int type, __s32 val)
{
	return nlmsg_attr_put(msg, type, sizeof(val), &val);
}

static int nlmsg_attr_put_string(struct nl_msg_buf *msg, int type, const char *str)
{
	return nlmsg_attr_put(msg, type, strlen(str) + 1, str);
}

static int find_genl_family(const char *name)
{
	struct {
		struct nlmsghdr nlh;
		struct genlmsg gnlh;
	} req = {
		.nlh.nlmsg_type = GENL_ID_CTRL,
		.nlh.nlmsg_len = sizeof(req),
		.nlh.nlmsg_flags = NLM_F_REQUEST,
		.nlh.nlmsg_seq = ++nl_seq,
		.gnlh.cmd = CTRL_CMD_GETFAMILY,
		.gnlh.version = 1,
	};
	struct nlattr *nla;
	char resp_buf[4096];
	struct nlmsghdr *resp_nlh = (void *)resp_buf;
	socklen_t len = sizeof(resp_buf);

	nla = (struct nlattr *)((char *)&req + sizeof(req));
	nla->nla_type = CTRL_ATTR_FAMILY_NAME;
	nla->nla_len = NLA_HDRLEN + strlen(name) + 1;
	strcpy((char *)nla + NLA_HDRLEN, name);
	req.nlh.nlmsg_len += NLA_ALIGN(nla->nla_len);

	if (send(nl_fd, &req, req.nlh.nlmsg_len, 0) < 0)
		return -1;
	if (recv(nl_fd, resp_buf, len, 0) < 0)
		return -1;

	if (resp_nlh->nlmsg_type == NLMSG_ERROR)
		return -1;

	/* Parse response to find family ID */
	struct nlattr *head = (struct nlattr *)((char *)resp_nlh +
		NLMSG_ALIGN(sizeof(*resp_nlh)) +
		NLMSG_ALIGN(sizeof(struct genlmsghdr)));
	int rem = resp_nlh->nlmsg_len - NLMSG_ALIGN(sizeof(*resp_nlh)) -
		  NLMSG_ALIGN(sizeof(struct genlmsghdr));

	while (rem >= (int)NLA_ALIGN(sizeof(struct nlattr))) {
		if (head->nla_type == CTRL_ATTR_FAMILY_ID)
			return *(__u32 *)((char *)head + NLA_HDRLEN);
		int step = NLA_ALIGN(head->nla_len);
		head = (struct nlattr *)((char *)head + step);
		rem -= step;
	}
	return -1;
}

/* ---- Commands ---- */

static int cmd_add(const char *devname, int vhid, int advbase, int advskew,
		   const char *password, const char *addr, const char *addr6)
{
	int family_id = find_genl_family(CARP_NL_FAMILY_NAME);
	if (family_id < 0) {
		fprintf(stderr, "CARP netlink family not found. Is carp module loaded?\n");
		return 1;
	}

	struct nl_msg_buf req = {
		.nlh.nlmsg_type = family_id,
		.nlh.nlmsg_flags = NLM_F_REQUEST,
		.nlh.nlmsg_seq = ++nl_seq,
		.nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN),
		.gnlh.cmd = CARP_NL_CMD_SET,
		.gnlh.version = 0,
	};

	nlmsg_attr_put_u32(&req, CARP_NL_VHID, vhid);
	nlmsg_attr_put_string(&req, CARP_NL_IFNAME, devname);
	nlmsg_attr_put_s32(&req, CARP_NL_ADVBASE, advbase);
	nlmsg_attr_put_s32(&req, CARP_NL_ADVSKEW, advskew);

	if (password)
		nlmsg_attr_put(&req, CARP_NL_KEY, strlen(password), password);

	if (addr) {
		struct in_addr a;
		if (inet_pton(AF_INET, addr, &a) == 1)
			nlmsg_attr_put(&req, CARP_NL_ADDR, sizeof(a), &a);
	}

	if (addr6) {
		struct in6_addr a6;
		if (inet_pton(AF_INET6, addr6, &a6) == 1)
			nlmsg_attr_put(&req, CARP_NL_ADDR6, sizeof(a6), &a6);
	}

	struct nl_msg_buf resp = {};
	int ret = nl_send_recv(&req, &resp);
	if (ret < 0) {
		fprintf(stderr, "Failed to add CARP: %s\n", strerror(-ret));
		return 1;
	}

	printf("CARP vhid %d added on %s\n", vhid, devname);
	return 0;
}

static int cmd_del(const char *devname, int vhid)
{
	/* Del is implemented by setting state to INIT with zero addresses.
	 * The kernel will clean up when no addresses remain. */
	int family_id = find_genl_family(CARP_NL_FAMILY_NAME);
	if (family_id < 0) {
		fprintf(stderr, "CARP netlink family not found. Is carp module loaded?\n");
		return 1;
	}

	struct nl_msg_buf req = {
		.nlh.nlmsg_type = family_id,
		.nlh.nlmsg_flags = NLM_F_REQUEST,
		.nlh.nlmsg_seq = ++nl_seq,
		.nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN),
		.gnlh.cmd = CARP_NL_CMD_SET,
		.gnlh.version = 0,
	};

	nlmsg_attr_put_u32(&req, CARP_NL_VHID, vhid);
	nlmsg_attr_put_string(&req, CARP_NL_IFNAME, devname);
	nlmsg_attr_put_u32(&req, CARP_NL_STATE, 0);  /* INIT = delete */

	struct nl_msg_buf resp = {};
	int ret = nl_send_recv(&req, &resp);
	if (ret < 0) {
		fprintf(stderr, "Failed to delete CARP: %s\n", strerror(-ret));
		return 1;
	}

	printf("CARP vhid %d deleted from %s\n", vhid, devname);
	return 0;
}

static int cmd_set(const char *devname, int vhid, int advbase, int advskew,
		   const char *password, int state, const char *addr,
		   const char *addr6)
{
	int family_id = find_genl_family(CARP_NL_FAMILY_NAME);
	if (family_id < 0) {
		fprintf(stderr, "CARP netlink family not found. Is carp module loaded?\n");
		return 1;
	}

	struct nl_msg_buf req = {
		.nlh.nlmsg_type = family_id,
		.nlh.nlmsg_flags = NLM_F_REQUEST,
		.nlh.nlmsg_seq = ++nl_seq,
		.nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN),
		.gnlh.cmd = CARP_NL_CMD_SET,
		.gnlh.version = 0,
	};

	nlmsg_attr_put_u32(&req, CARP_NL_VHID, vhid);
	nlmsg_attr_put_string(&req, CARP_NL_IFNAME, devname);

	if (advbase >= 0)
		nlmsg_attr_put_s32(&req, CARP_NL_ADVBASE, advbase);
	if (advskew >= 0)
		nlmsg_attr_put_s32(&req, CARP_NL_ADVSKEW, advskew);
	if (state >= 0)
		nlmsg_attr_put_u32(&req, CARP_NL_STATE, state);
	if (password)
		nlmsg_attr_put(&req, CARP_NL_KEY, strlen(password), password);
	if (addr) {
		struct in_addr a;
		if (inet_pton(AF_INET, addr, &a) == 1)
			nlmsg_attr_put(&req, CARP_NL_ADDR, sizeof(a), &a);
	}
	if (addr6) {
		struct in6_addr a6;
		if (inet_pton(AF_INET6, addr6, &a6) == 1)
			nlmsg_attr_put(&req, CARP_NL_ADDR6, sizeof(a6), &a6);
	}

	struct nl_msg_buf resp = {};
	int ret = nl_send_recv(&req, &resp);
	if (ret < 0) {
		fprintf(stderr, "Failed to set CARP: %s\n", strerror(-ret));
		return 1;
	}

	printf("CARP vhid %d on %s updated\n", vhid, devname);
	return 0;
}

static int cmd_status(const char *devname, int vhid)
{
	int family_id = find_genl_family(CARP_NL_FAMILY_NAME);
	if (family_id < 0) {
		fprintf(stderr, "CARP netlink family not found. Is carp module loaded?\n");
		return 1;
	}

	struct nl_msg_buf req = {
		.nlh.nlmsg_type = family_id,
		.nlh.nlmsg_flags = NLM_F_REQUEST,
		.nlh.nlmsg_seq = ++nl_seq,
		.nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN),
		.gnlh.cmd = CARP_NL_CMD_GET,
		.gnlh.version = 0,
	};

	if (devname)
		nlmsg_attr_put_string(&req, CARP_NL_IFNAME, devname);
	if (vhid > 0)
		nlmsg_attr_put_u32(&req, CARP_NL_VHID, vhid);

	struct nl_msg_buf resp = {};
	int ret = nl_send_recv(&req, &resp);
	if (ret < 0) {
		fprintf(stderr, "Failed to get CARP status: %s\n", strerror(-ret));
		return 1;
	}

	/* Parse response */
	struct nlattr *head = (struct nlattr *)((char *)&resp +
		NLMSG_ALIGN(sizeof(resp.nlh)) +
		NLMSG_ALIGN(sizeof(resp.gnlh)));
	int rem = resp.nlh.nlmsg_len - NLMSG_ALIGN(sizeof(resp.nlh)) -
		  NLMSG_ALIGN(sizeof(resp.gnlh));

	const char *ifname = NULL;
	__u32 rvhid = 0, rstate = 0;
	__s32 radvbase = 0, radvskew = 0;
	struct in_addr raddr = {};
	struct in6_addr raddr6 = {};
	static const char *states[] = { "INIT", "BACKUP", "MASTER" };
	int has_addr = 0, has_addr6 = 0;

	while (rem >= (int)NLA_ALIGN(sizeof(struct nlattr))) {
		int align = NLA_ALIGN(head->nla_len);
		if (align > rem)
			break;
		switch (head->nla_type) {
		case CARP_NL_IFNAME:
			ifname = (const char *)((char *)head + NLA_HDRLEN);
			break;
		case CARP_NL_VHID:
			rvhid = *(__u32 *)((char *)head + NLA_HDRLEN);
			break;
		case CARP_NL_STATE:
			rstate = *(__u32 *)((char *)head + NLA_HDRLEN);
			break;
		case CARP_NL_ADVBASE:
			radvbase = *(__s32 *)((char *)head + NLA_HDRLEN);
			break;
		case CARP_NL_ADVSKEW:
			radvskew = *(__s32 *)((char *)head + NLA_HDRLEN);
			break;
		case CARP_NL_ADDR:
			memcpy(&raddr, (char *)head + NLA_HDRLEN, sizeof(raddr));
			has_addr = 1;
			break;
		case CARP_NL_ADDR6:
			memcpy(&raddr6, (char *)head + NLA_HDRLEN, sizeof(raddr6));
			has_addr6 = 1;
			break;
		}
		head = (struct nlattr *)((char *)head + align);
		rem -= align;
	}

	if (rstate <= 2) {
		char addr_buf[INET6_ADDRSTRLEN];
		printf("%s\tvhid %d\tstate %s\tadvbase %d\tadvskew %d",
		       ifname ? ifname : "?", rvhid, states[rstate],
		       radvbase, radvskew);
		if (has_addr) {
			inet_ntop(AF_INET, &raddr, addr_buf, sizeof(addr_buf));
			printf("\taddr %s", addr_buf);
		}
		if (has_addr6) {
			inet_ntop(AF_INET6, &raddr6, addr_buf, sizeof(addr_buf));
			printf("\taddr6 %s", addr_buf);
		}
		printf("\n");
	} else {
		fprintf(stderr, "No CARP VHID %d found on %s\n",
			vhid, devname ? devname : "*");
		return 1;
	}

	return 0;
}

/* ---- Main ---- */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <command> [options]\n\n"
		"Commands:\n"
		"  add <dev> <vhid>      Add CARP VHID to interface\n"
		"  del <dev> <vhid>      Remove CARP VHID from interface\n"
		"  set <dev> <vhid>      Change CARP parameters\n"
		"  status [dev] [vhid]   Show CARP status\n"
		"\n"
		"Options:\n"
		"  --advbase <n>         Advertisement interval (1-255 seconds)\n"
		"  --advskew <n>         Advertisement skew (0-254, in 1/256 seconds)\n"
		"  --password <key>      Authentication key (max 20 chars)\n"
		"  --state <s>           Force state: MASTER or BACKUP\n"
		"  --addr <ip>           IPv4 address\n"
		"  --addr6 <ip6>         IPv6 address\n",
		prog);
}

int main(int argc, char *argv[])
{
	const char *cmd;
	const char *devname = NULL;
	int vhid = -1;
	int advbase = 1;
	int advskew = 0;
	const char *password = NULL;
	const char *addr = NULL;
	const char *addr6 = NULL;
	int state = -1;
	int opt;

	static struct option long_opts[] = {
		{ "advbase",  required_argument, NULL, 'b' },
		{ "advskew",  required_argument, NULL, 'k' },
		{ "password", required_argument, NULL, 'p' },
		{ "state",    required_argument, NULL, 's' },
		{ "addr",     required_argument, NULL, '4' },
		{ "addr6",    required_argument, NULL, '6' },
		{ "help",     no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	cmd = argv[1];

	/* Reset getopt for subcommand parsing */
	argc--;
	argv++;
	optind = 1;

	while ((opt = getopt_long(argc, argv, "+b:k:p:s:4:6:h", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'b':
			advbase = atoi(optarg);
			break;
		case 'k':
			advskew = atoi(optarg);
			break;
		case 'p':
			password = optarg;
			break;
		case 's':
			if (strcasecmp(optarg, "MASTER") == 0)
				state = 2;
			else if (strcasecmp(optarg, "BACKUP") == 0)
				state = 1;
			else if (strcasecmp(optarg, "INIT") == 0)
				state = 0;
			else {
				fprintf(stderr, "Unknown state: %s\n", optarg);
				return 1;
			}
			break;
		case '4':
			addr = optarg;
			break;
		case '6':
			addr6 = optarg;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	/* Get devname and vhid from remaining args */
	if (optind < argc)
		devname = argv[optind++];
	if (optind < argc)
		vhid = atoi(argv[optind++]);

	/* Open netlink socket */
	nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (nl_fd < 0) {
		perror("socket");
		return 1;
	}

	struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK,
		.nl_pid = 0,
		.nl_groups = 0,
	};
	if (bind(nl_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		close(nl_fd);
		return 1;
	}

	int ret = 0;

	if (strcmp(cmd, "add") == 0) {
		if (!devname || vhid < 0) {
			fprintf(stderr, "add requires <dev> and <vhid>\n");
			ret = 1;
			goto out;
		}
		if (vhid < 1 || vhid > CARP_MAXVHID) {
			fprintf(stderr, "vhid must be 1-%d\n", CARP_MAXVHID);
			ret = 1;
			goto out;
		}
		ret = cmd_add(devname, vhid, advbase, advskew, password, addr, addr6);
	} else if (strcmp(cmd, "del") == 0) {
		if (!devname || vhid < 0) {
			fprintf(stderr, "del requires <dev> and <vhid>\n");
			ret = 1;
			goto out;
		}
		ret = cmd_del(devname, vhid);
	} else if (strcmp(cmd, "set") == 0) {
		if (!devname || vhid < 0) {
			fprintf(stderr, "set requires <dev> and <vhid>\n");
			ret = 1;
			goto out;
		}
		ret = cmd_set(devname, vhid, advbase, advskew, password,
			      state, addr, addr6);
	} else if (strcmp(cmd, "status") == 0) {
		ret = cmd_status(devname, vhid > 0 ? vhid : 0);
	} else {
		fprintf(stderr, "Unknown command: %s\n", cmd);
		usage(argv[0]);
		ret = 1;
	}

out:
	close(nl_fd);
	return ret;
}
