/* SPDX-License-Identifier: BSD-2-Clause */
#include "carpd.h"

int cmd_add(const char *devname, int vhid, int advbase, int advskew,
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

int cmd_del(const char *devname, int vhid)
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

int cmd_set(const char *devname, int vhid, int advbase, int advskew,
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

int cmd_status(const char *devname, int vhid)
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
