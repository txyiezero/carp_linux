/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * CARP configuration tool for Linux.
 * Mirrors FreeBSD ifconfig carp.c behavior.
 *
 * Usage:
 *   carp_config -v <vhid> [-b <advbase>] [-s <advskew>] [-k <key>] <interface>
 *   carp_config -g [-v <vhid>] <interface>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>

/* Must match kernel header */
#define SIOCSVH	_IOWR('i', 245, struct ifreq)
#define SIOCGVH	_IOWR('i', 246, struct ifreq)

struct carpreq {
	int      carpr_count;
	int      carpr_vhid;
	int      carpr_state;
	int      carpr_advskew;
	int      carpr_advbase;
	unsigned char carpr_key[20];
};

static const char *carp_states[] = { "INIT", "BACKUP", "MASTER" };

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [options] <interface>\n"
		"Options:\n"
		"  -v <vhid>      Virtual Host ID (1-255)\n"
		"  -b <advbase>   Advertisement base interval in seconds (1-255)\n"
		"  -s <advskew>   Advertisement skew (0-240)\n"
		"  -k <key>       Authentication key\n"
		"  -S <state>     Force state: INIT, BACKUP, MASTER\n"
		"  -g             Get CARP status\n"
		"  -h             Show this help\n"
		"\n"
		"Examples:\n"
		"  %s -v 1 -b 1 -s 0 -k mysecret eth0\n"
		"  %s -g -v 1 eth0\n",
		prog, prog, prog);
}

int main(int argc, char *argv[])
{
	int sockfd;
	struct ifreq ifr;
	struct carpreq carpr;
	int opt;
	int vhid = -1;
	int advbase = 1;
	int advskew = 0;
	int state = -1;
	int get_status = 0;
	char *key = NULL;
	char *interface = NULL;

	while ((opt = getopt(argc, argv, "v:b:s:S:k:gh")) != -1) {
		switch (opt) {
		case 'v':
			vhid = atoi(optarg);
			break;
		case 'b':
			advbase = atoi(optarg);
			break;
		case 's':
			advskew = atoi(optarg);
			break;
		case 'S':
			if (strcasecmp(optarg, "INIT") == 0)
				state = 0;
			else if (strcasecmp(optarg, "BACKUP") == 0)
				state = 1;
			else if (strcasecmp(optarg, "MASTER") == 0)
				state = 2;
			else {
				fprintf(stderr, "Unknown state: %s\n", optarg);
				return 1;
			}
			break;
		case 'k':
			key = optarg;
			break;
		case 'g':
			get_status = 1;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Error: interface required\n");
		usage(argv[0]);
		return 1;
	}

	interface = argv[optind];

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("socket");
		return 1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

	if (get_status) {
		memset(&carpr, 0, sizeof(carpr));
		carpr.carpr_vhid = vhid > 0 ? vhid : 0;
		ifr.ifr_data = (caddr_t)&carpr;

		if (ioctl(sockfd, SIOCGVH, &ifr) < 0) {
			perror("ioctl SIOCGVH");
			close(sockfd);
			return 1;
		}

		printf("carp: %s vhid %d advbase %d advskew %d state %s\n",
		       interface, carpr.carpr_vhid,
		       carpr.carpr_advbase, carpr.carpr_advskew,
		       (carpr.carpr_state >= 0 && carpr.carpr_state <= 2) ?
		       carp_states[carpr.carpr_state] : "UNKNOWN");
	} else {
		if (vhid <= 0 || vhid > 255) {
			fprintf(stderr, "Error: vhid must be 1-255\n");
			close(sockfd);
			return 1;
		}

		memset(&carpr, 0, sizeof(carpr));
		carpr.carpr_vhid = vhid;
		carpr.carpr_advbase = advbase;
		carpr.carpr_advskew = advskew;
		carpr.carpr_state = state >= 0 ? state : 0;

		if (key)
			strncpy((char *)carpr.carpr_key, key,
				sizeof(carpr.carpr_key) - 1);

		ifr.ifr_data = (caddr_t)&carpr;

		if (ioctl(sockfd, SIOCSVH, &ifr) < 0) {
			perror("ioctl SIOCSVH");
			close(sockfd);
			return 1;
		}

		printf("CARP configured on %s: vhid %d advbase %d advskew %d\n",
		       interface, vhid, advbase, advskew);
	}

	close(sockfd);
	return 0;
}
