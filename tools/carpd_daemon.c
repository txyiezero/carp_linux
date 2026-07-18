/* SPDX-License-Identifier: BSD-2-Clause */
#include "carpd.h"

#define UEVENT_BUF_SIZE 2048

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
	(void)sig;
	running = 0;
}

static int run_cmd(const char *cmd)
{
	char buf[256];
	int ret;
	snprintf(buf, sizeof(buf), "%s 2>&1", cmd);
	ret = system(buf);
	if (ret != 0)
		fprintf(stderr, "Command failed: %s (exit %d)\n", cmd, ret);
	return ret;
}

void manage_address(const char *devname, int vhid,
		    const char *vip, int is_add)
{
	char cmd[256];
	const char *action = is_add ? "add" : "del";

	if (strchr(vip, ':'))
		snprintf(cmd, sizeof(cmd), "ip -6 addr %s %s/128 dev %s",
			 action, vip, devname);
	else
		snprintf(cmd, sizeof(cmd), "ip -4 addr %s %s/32 dev %s",
			 action, vip, devname);

	printf("carpd: VHID %d on %s -> %s %s\n", vhid, devname, action, vip);
	run_cmd(cmd);
}

void handle_uevent(const char *envp)
{
	char state[32] = {0};
	char vhid_str[16] = {0};
	char ifname[IFNAMSIZ] = {0};
	const char *p;
	int vhid = 0;

	p = envp;
	while (p && *p) {
		if (strncmp(p, "CARP_STATE=", 11) == 0)
			snprintf(state, sizeof(state), "%s", p + 11);
		else if (strncmp(p, "VHID=", 5) == 0)
			snprintf(vhid_str, sizeof(vhid_str), "%s", p + 5);
		else if (strncmp(p, "IFNAME=", 7) == 0)
			snprintf(ifname, sizeof(ifname), "%s", p + 7);
		p += strlen(p) + 1;
	}

	if (!state[0] || !ifname[0])
		return;

	vhid = atoi(vhid_str);
	if (vhid <= 0)
		return;

	printf("carpd: state change -> %s vhid %d on %s\n", state, vhid, ifname);

	/* Query virtual IP from kernel via netlink */
	{
		char vip4[INET_ADDRSTRLEN] = {0};
		char vip6[INET6_ADDRSTRLEN] = {0};

		if (query_vip(ifname, vhid, vip4, sizeof(vip4), vip6, sizeof(vip6)) == 0) {
			if (strcmp(state, "MASTER") == 0) {
				if (vip4[0])
					manage_address(ifname, vhid, vip4, 1);
				if (vip6[0])
					manage_address(ifname, vhid, vip6, 1);
			} else if (strcmp(state, "BACKUP") == 0 || strcmp(state, "INIT") == 0) {
				if (vip4[0])
					manage_address(ifname, vhid, vip4, 0);
				if (vip6[0])
					manage_address(ifname, vhid, vip6, 0);
			}
		} else {
			fprintf(stderr, "carpd: failed to query VIP for vhid %d on %s\n",
				vhid, ifname);
		}
	}
}

int cmd_daemon(void)
{
	int nl_sock;
	struct sockaddr_nl sa;
	char buf[UEVENT_BUF_SIZE];
	struct iovec iov = { buf, sizeof(buf) };
	struct msghdr msg = {
		.msg_name = &sa,
		.msg_namelen = sizeof(sa),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	if (nl_sock < 0) {
		perror("socket(NETLINK_KOBJECT_UEVENT)");
		return 1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_pid = getpid();
	sa.nl_groups = 1;

	if (bind(nl_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		close(nl_sock);
		return 1;
	}

	printf("carpd: daemon started, listening for CARP state changes...\n");

	while (running) {
		int len = recvmsg(nl_sock, &msg, 0);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			perror("recvmsg");
			break;
		}
		if (strstr(buf, "CARP_STATE="))
			handle_uevent(buf);
	}

	close(nl_sock);
	printf("carpd: daemon stopped\n");
	return 0;
}
