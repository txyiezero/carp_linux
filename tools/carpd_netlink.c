/* SPDX-License-Identifier: BSD-2-Clause */
#include "carpd.h"

int nl_fd;
__u32 nl_seq;

/* ---- Netlink helpers ---- */

int nl_send_recv(struct nl_msg_buf *req, struct nl_msg_buf *resp)
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

int nlmsg_attr_put(struct nl_msg_buf *msg, int type, int len, const void *data)
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

int nlmsg_attr_put_u32(struct nl_msg_buf *msg, int type, __u32 val)
{
	return nlmsg_attr_put(msg, type, sizeof(val), &val);
}

int nlmsg_attr_put_s32(struct nl_msg_buf *msg, int type, __s32 val)
{
	return nlmsg_attr_put(msg, type, sizeof(val), &val);
}

int nlmsg_attr_put_string(struct nl_msg_buf *msg, int type, const char *str)
{
	return nlmsg_attr_put(msg, type, strlen(str) + 1, str);
}

int find_genl_family(const char *name)
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

int query_vip(const char *devname, int vhid,
	      char *addr4, size_t addr4_len,
	      char *addr6, size_t addr6_len)
{
	int family_id = find_genl_family(CARP_NL_FAMILY_NAME);
	if (family_id < 0)
		return -1;

	struct nl_msg_buf req = {
		.nlh.nlmsg_type = family_id,
		.nlh.nlmsg_flags = NLM_F_REQUEST,
		.nlh.nlmsg_seq = ++nl_seq,
		.nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN),
		.gnlh.cmd = CARP_NL_CMD_GET,
		.gnlh.version = 0,
	};

	nlmsg_attr_put_string(&req, CARP_NL_IFNAME, devname);
	nlmsg_attr_put_u32(&req, CARP_NL_VHID, vhid);

	struct nl_msg_buf resp = {};
	int ret = nl_send_recv(&req, &resp);
	if (ret < 0)
		return -1;

	struct nlattr *head = (struct nlattr *)((char *)&resp +
		NLMSG_ALIGN(sizeof(resp.nlh)) +
		NLMSG_ALIGN(sizeof(resp.gnlh)));
	int rem = resp.nlh.nlmsg_len - NLMSG_ALIGN(sizeof(resp.nlh)) -
		  NLMSG_ALIGN(sizeof(resp.gnlh));

	addr4[0] = '\0';
	addr6[0] = '\0';

	while (rem >= (int)NLA_ALIGN(sizeof(struct nlattr))) {
		int align = NLA_ALIGN(head->nla_len);
		if (align > rem)
			break;
		if (head->nla_type == CARP_NL_ADDR) {
			struct in_addr a;
			memcpy(&a, (char *)head + NLA_HDRLEN, sizeof(a));
			inet_ntop(AF_INET, &a, addr4, addr4_len);
		} else if (head->nla_type == CARP_NL_ADDR6) {
			struct in6_addr a6;
			memcpy(&a6, (char *)head + NLA_HDRLEN, sizeof(a6));
			inet_ntop(AF_INET6, &a6, addr6, addr6_len);
		}
		head = (struct nlattr *)((char *)head + align);
		rem -= align;
	}

	return 0;
}
