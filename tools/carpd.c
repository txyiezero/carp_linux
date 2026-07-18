/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * carpd - CARP daemon for Linux
 * Main entry point: CLI parsing and command dispatch.
 */
#include "carpd.h"

void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <command> [options]\n\n"
		"Commands:\n"
		"  add <dev> <vhid>      Add CARP VHID to interface\n"
		"  del <dev> <vhid>      Remove CARP VHID from interface\n"
		"  set <dev> <vhid>      Change CARP parameters\n"
		"  status [dev] [vhid]   Show CARP state\n"
		"  daemon                Listen for state changes and manage addresses\n"
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
			fprintf(stderr, "IPv6 address setting not yet implemented\n");
			return 1;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

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

	if (strcmp(cmd, "add") == 0 || strcmp(cmd, "set") == 0) {
		if (!devname || vhid < 0) {
			fprintf(stderr, "%s requires <dev> and <vhid>\n", cmd);
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
	} else if (strcmp(cmd, "daemon") == 0) {
		ret = cmd_daemon();
	} else {
		fprintf(stderr, "Unknown command: %s\n", cmd);
		usage(argv[0]);
		ret = 1;
	}

out:
	close(nl_fd);
	return ret;
}
