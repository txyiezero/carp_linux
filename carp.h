/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2002 Michael Shalayeff.
 * Copyright (c) 2003 Ryan McBride.
 * Copyright (c) 2011 Gleb Smirnoff <glebius@FreeBSD.org>
 * All rights reserved.
 *
 * Linux port: Minimal changes from FreeBSD sys/netinet/ip_carp.h
 */

#ifndef _LINUX_CARP_H
#define _LINUX_CARP_H

#include <linux/types.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/crypto.h>

/*
 * The CARP header layout is as follows (same as FreeBSD):
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |Version| Type  | VirtualHostID |    AdvSkew    |    Auth Len   |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   Reserved    |     AdvBase   |          Checksum             |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                         Counter (1)                           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                         Counter (2)                           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                        SHA-1 HMAC (1)                         |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                        SHA-1 HMAC (2)                         |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                        SHA-1 HMAC (3)                         |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                        SHA-1 HMAC (4)                         |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                        SHA-1 HMAC (5)                         |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct carp_header {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	carp_type:4,
		carp_version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8	carp_version:4,
		carp_type:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	__u8	carp_vhid;	/* virtual host id */
	__u8	carp_advskew;	/* advertisement skew */
	__u8	carp_authlen;	/* size of counter+md, 32bit chunks */
	__u8	carp_pad1;	/* reserved */
	__u8	carp_advbase;	/* advertisement interval */
	__be16	carp_cksum;
	__be32	carp_counter[2];
	__u8	carp_md[20];	/* SHA1 HMAC */
} __packed;

/* Verify header size matches FreeBSD */
_Static_assert(sizeof(struct carp_header) == 36, "carp_header size mismatch");

#define CARP_DFLTTL		255
#define CARP_VERSION		2
#define CARP_ADVERTISEMENT	0x01
#define CARP_KEY_LEN		20	/* a sha1 hash of a passphrase */
#define CARP_DFLTINTV		1
#define CARP_MAXVHID		255
#define CARP_MAXSKEW		240
#define CARP_HMAC_PAD		64

#ifndef IPPROTO_CARP
#define IPPROTO_CARP		112
#endif

#ifndef ETH_P_CARP
#define ETH_P_CARP		0x08FF
#endif

#define CARP_STATES		"INIT", "BACKUP", "MASTER"
#define CARP_MAXSTATE		2

/* IPv4 multicast address: 224.0.0.18 */
#define INADDR_CARP_GROUP	0xe0000012

/* Statistics (mirrors FreeBSD struct carpstats) */
struct carpstats {
	__u64	carps_ipackets;		/* total input packets, IPv4 */
	__u64	carps_ipackets6;	/* total input packets, IPv6 */
	__u64	carps_badif;		/* wrong interface */
	__u64	carps_badttl;		/* TTL is not CARP_DFLTTL */
	__u64	carps_hdrops;		/* packets shorter than hdr */
	__u64	carps_badsum;		/* bad checksum */
	__u64	carps_badver;		/* bad (incl unsupp) version */
	__u64	carps_badlen;		/* data length does not match */
	__u64	carps_badauth;		/* bad authentication */
	__u64	carps_badvhid;		/* bad VHID */
	__u64	carps_badaddrs;		/* bad address list */
	__u64	carps_opackets;		/* total output packets, IPv4 */
	__u64	carps_opackets6;	/* total output packets, IPv6 */
	__u64	carps_onomem;		/* no memory */
	__u64	carps_ostates;		/* total state updates sent */
	__u64	carps_preempt;		/* if enabled, preemptions */
};

/* Configuration structure for SIOCSVH SIOCGVH (mirrors FreeBSD struct carpreq) */
struct carpreq {
	int		carpr_count;
	int		carpr_vhid;
	int		carpr_state;
	int		carpr_advskew;
	int		carpr_advbase;
	unsigned char	carpr_key[CARP_KEY_LEN];
};

#define SIOCSVH	_IOWR('i', 245, struct ifreq)
#define SIOCGVH	_IOWR('i', 246, struct ifreq)

/* CARP softc structure (mirrors FreeBSD struct carp_softc) */
struct carp_softc {
	struct net_device	*sc_carpdev;	/* Pointer to parent net_device */
	struct list_head	sc_list;	/* On global carp_list */
	struct spinlock		sc_mtx;		/* Per-softc lock */

	int			sc_vhid;
	int			sc_advskew;
	int			sc_advbase;
	struct in_addr		sc_carpaddr;	/* IPv4 CARP multicast */
	struct in6_addr		sc_carpaddr6;	/* IPv6 CARP multicast */

	int			sc_naddrs;
	int			sc_naddrs6;

	enum { INIT = 0, BACKUP, MASTER } sc_state;
	int			sc_suppress;
	int			sc_sendad_errors;
#define	CARP_SENDAD_MAX_ERRORS	3
	int			sc_sendad_success;
#define	CARP_SENDAD_MIN_SUCCESS	3

	int			sc_init_counter;
	__u64			sc_counter;

	/* authentication */
	__u8			sc_key[CARP_KEY_LEN];
	__u8			sc_pad[CARP_HMAC_PAD];
	struct crypto_shash	*sc_tfm;

	/* Timers (replacing FreeBSD callouts) */
	struct timer_list	sc_ad_tmo;	/* Advertising timeout */
	struct timer_list	sc_md_tmo;	/* Master down timeout (IPv4) */
	struct timer_list	sc_md6_tmo;	/* Master down timeout (IPv6) */

	/* Virtual MAC address */
	__u8			sc_mac[ETH_ALEN];
};

/* Module parameters */
extern int carp_allow;
extern int carp_preempt;
extern int carp_log;

/* Logging macros */
#define CARP_LOG(fmt, ...) do { \
	if (carp_log > 0) \
		pr_info("carp: " fmt "\n", ##__VA_ARGS__); \
} while (0)

#define CARP_DEBUG(fmt, ...) do { \
	if (carp_log > 1) \
		pr_debug("carp: " fmt "\n", ##__VA_ARGS__); \
} while (0)

/* HMAC function prototypes */
int  carp_hmac_init(struct carp_softc *sc);
void carp_hmac_free(struct carp_softc *sc);
void carp_hmac_prepare(struct carp_softc *sc);
int  carp_hmac_generate(struct carp_softc *sc, __u32 counter[2],
			 unsigned char md[20]);
int  carp_hmac_verify(struct carp_softc *sc, __u32 counter[2],
		      unsigned char md[20]);

#endif /* _LINUX_CARP_H */
