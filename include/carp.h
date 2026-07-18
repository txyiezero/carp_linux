/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * CARP (Common Address Redundancy Protocol) - Linux port
 * Original: FreeBSD 14.4 sys/netinet/ip_carp.h
 * Ported to Linux 6.12
 */

#ifndef _UAPI_LINUX_CARP_H
#define _UAPI_LINUX_CARP_H

#include <linux/types.h>

struct carp_header {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	carp_type:4,
		carp_version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	carp_version:4,
		carp_type:4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
	__u8	carp_vhid;
	__u8	carp_advskew;
	__u8	carp_authlen;
	__u8	carp_pad1;
	__u8	carp_advbase;
	__be16	carp_cksum;
	__be32	carp_counter[2];
	__u8	carp_md[20];
} __attribute__((packed));

#define CARP_HDR_LEN		36
#define CARP_DFLTTL		255
#define CARP_VERSION		2
#define CARP_ADVERTISEMENT	0x01
#define CARP_KEY_LEN		20
#define CARP_DFLTINTV		1
#define CARP_MAXVHID		255
#define CARP_MAXSKEW		240
#define CARP_MAXSTATE		2

#define CARP_STATE_INIT		0
#define CARP_STATE_BACKUP	1
#define CARP_STATE_MASTER	2

struct carpstats {
	__u64	carps_ipackets;
	__u64	carps_ipackets6;
	__u64	carps_badif;
	__u64	carps_badttl;
	__u64	carps_hdrops;
	__u64	carps_badsum;
	__u64	carps_badver;
	__u64	carps_badlen;
	__u64	carps_badauth;
	__u64	carps_badvhid;
	__u64	carps_badaddrs;
	__u64	carps_opackets;
	__u64	carps_opackets6;
	__u64	carps_onomem;
	__u64	carps_ostates;
	__u64	carps_preempt;
};

#define CARP_NL_FAMILY_NAME	"carp"

enum {
	CARP_NL_CMD_UNSPEC = 0,
	CARP_NL_CMD_GET    = 1,
	CARP_NL_CMD_SET    = 2,
	__CARP_NL_CMD_MAX,
};
#define CARP_NL_CMD_MAX (__CARP_NL_CMD_MAX - 1)

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

#endif /* _UAPI_LINUX_CARP_H */
