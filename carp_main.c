/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2002 Michael Shalayeff.
 * Copyright (c) 2003 Ryan McBride.
 * Copyright (c) 2011 Gleb Smirnoff <glebius@FreeBSD.org>
 * All rights reserved.
 *
 * Linux port: Minimal changes from FreeBSD sys/netinet/ip_carp.c
 * This is a Linux kernel module implementing the CARP protocol.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/igmp.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/socket.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/arp.h>
#include <net/checksum.h>
#include <net/net_namespace.h>

#include "carp.h"

/*
 * Global list of all CARP softcs (mirrors FreeBSD carp_list).
 */
static LIST_HEAD(carp_list);
static DEFINE_SPINLOCK(carp_mtx);

/*
 * Module parameters (mirrors FreeBSD sysctl variables).
 */
int carp_allow = 1;
module_param(carp_allow, int, 0644);
MODULE_PARM_DESC(carp_allow, "Accept incoming CARP packets (default=1)");

int carp_preempt = 0;
module_param(carp_preempt, int, 0644);
MODULE_PARM_DESC(carp_preempt, "Preempt slower masters (default=0)");

int carp_log = 1;
module_param(carp_log, int, 0644);
MODULE_PARM_DESC(carp_log, "CARP log level (default=1)");

/* Statistics (mirrors FreeBSD VNET_PCPUSTAT) */
static struct carpstats carpstats;

#define CARPSTATS_ADD(name, val) (carpstats.name += (val))
#define CARPSTATS_INC(name)	CARPSTATS_ADD(name, 1)

/* Locking macros (mirrors FreeBSD CARP_LOCK/CARP_UNLOCK) */
#define CARP_LOCK_INIT(sc)	spin_lock_init(&(sc)->sc_mtx)
#define CARP_LOCK(sc)		spin_lock_bh(&(sc)->sc_mtx)
#define CARP_UNLOCK(sc)		spin_unlock_bh(&(sc)->sc_mtx)
#define CARP_LOCK_ASSERT(sc)	/* no-op in Linux */

/* Iteration macro (mirrors FreeBSD CARP_FOREACH_IFA - adapted) */
#define CARP_FOREACH_SC(sc) \
	list_for_each_entry(sc, &carp_list, sc_list)

/*
 * Demote skew calculation (mirrors FreeBSD DEMOTE_ADVSKEW macro).
 * Since Linux doesn't have global demotion, this just returns advskew.
 */
static inline int DEMOTE_ADVSKEW(struct carp_softc *sc)
{
	return sc->sc_advskew;
}

/*
 * Check if address is CARP multicast.
 */
static inline int carp_is_multicast_v4(struct in_addr *addr)
{
	return IN_MULTICAST(ntohl(addr->s_addr));
}

/* ================================================================
 * CARP advertisement send (mirrors FreeBSD carp_send_ad_locked)
 * ================================================================ */

static void carp_send_ad_locked(struct carp_softc *sc)
{
	struct sk_buff *skb;
	struct carp_header ch, *ch_ptr;
	struct iphdr *iph;
	struct ethhdr *eth;
	int len, advskew;

	CARP_LOCK_ASSERT(sc);

	advskew = DEMOTE_ADVSKEW(sc);

	/* Build CARP header (mirrors FreeBSD carp_send_ad_locked) */
	ch.carp_version = CARP_VERSION;
	ch.carp_type = CARP_ADVERTISEMENT;
	ch.carp_vhid = sc->sc_vhid;
	ch.carp_advbase = sc->sc_advbase;
	ch.carp_advskew = advskew;
	ch.carp_authlen = 7;
	ch.carp_pad1 = 0;
	ch.carp_cksum = 0;

	if (sc->sc_naddrs) {
		len = sizeof(struct iphdr) + sizeof(ch);

		skb = netdev_alloc_skb(sc->sc_carpdev,
				       len + LL_RESERVED_SPACE(sc->sc_carpdev));
		if (!skb) {
			CARPSTATS_INC(carps_onomem);
			goto resched;
		}

		skb_reserve(skb, LL_RESERVED_SPACE(sc->sc_carpdev));
		skb->protocol = htons(ETH_P_IP);
		skb->dev = sc->sc_carpdev;
		skb->pkt_type = PACKET_HOST;

		/* Ethernet header */
		skb_push(skb, ETH_HLEN);
		skb_reset_mac_header(skb);
		eth = eth_hdr(skb);
		ether_addr_copy(eth->h_dest, sc->sc_carpdev->dev_addr);
		eth->h_source[0] = 0; eth->h_source[1] = 0;
		eth->h_source[2] = 0x5e;
		eth->h_source[3] = 0; eth->h_source[4] = 1;
		eth->h_source[5] = sc->sc_vhid;
		eth->h_proto = htons(ETH_P_IP);

		/* IP header */
		skb_put(skb, sizeof(struct iphdr));
		iph = ip_hdr(skb);
		memset(iph, 0, sizeof(*iph));
		iph->version  = 4;
		iph->ihl      = 5;
		iph->tos      = 0;
		iph->tot_len  = htons(len);
		iph->ttl      = CARP_DFLTTL;
		iph->protocol = IPPROTO_CARP; /* 112 */
		iph->saddr    = sc->sc_carpaddr.s_addr;
		iph->daddr    = sc->sc_carpaddr.s_addr;
		iph->check    = 0;
		iph->check    = ip_fast_csum((unsigned char *)iph, iph->ihl);

		/* CARP header */
		skb_put(skb, sizeof(ch));
		ch_ptr = (struct carp_header *)(iph + 1);

		/* Prepare and copy */
		if (sc->sc_init_counter) {
			sc->sc_counter = get_random_u64();
			sc->sc_init_counter = 0;
		} else {
			sc->sc_counter++;
		}

		ch_ptr->carp_version = ch.carp_version;
		ch_ptr->carp_type    = ch.carp_type;
		ch_ptr->carp_vhid    = ch.carp_vhid;
		ch_ptr->carp_advskew = ch.carp_advskew;
		ch_ptr->carp_advbase = ch.carp_advbase;
		ch_ptr->carp_authlen = ch.carp_authlen;
		ch_ptr->carp_pad1    = ch.carp_pad1;
		ch_ptr->carp_counter[0] = htonl((__u32)(sc->sc_counter >> 32));
		ch_ptr->carp_counter[1] = htonl((__u32)(sc->sc_counter & 0xffffffff));

		carp_hmac_generate(sc, ch_ptr->carp_counter, ch_ptr->carp_md);

		/* CARP checksum */
		ch_ptr->carp_cksum = 0;
		ch_ptr->carp_cksum = csum_tcpudp_magic(
			sc->sc_carpaddr.s_addr, sc->sc_carpaddr.s_addr,
			sizeof(ch), IPPROTO_CARP,
			csum_partial(ch_ptr, sizeof(ch), 0));

		CARPSTATS_INC(carps_opackets);

		if (dev_queue_xmit(skb) < 0) {
			CARPSTATS_INC(carps_onomem);
		}
	}

resched:
	/* Schedule next advertisement (mirrors FreeBSD callout_reset) */
	if (sc->sc_state == MASTER) {
		unsigned long timeout = sc->sc_advbase * HZ +
					(advskew * HZ / 256);
		mod_timer(&sc->sc_ad_tmo, jiffies + timeout);
	}
}

/* Timer callback: periodic advertisement (mirrors FreeBSD carp_send_ad) */
static void carp_send_ad(struct timer_list *t)
{
	struct carp_softc *sc = from_timer(sc, t, sc_ad_tmo);

	CARP_LOCK(sc);
	if (sc->sc_state == MASTER)
		carp_send_ad_locked(sc);
	CARP_UNLOCK(sc);
}

/* ================================================================
 * CARP advertisement receive (mirrors FreeBSD carp_input_c)
 * ================================================================ */

static int carp_input_c(struct sk_buff *skb, struct carp_header *ch,
			 sa_family_t af, int ttl)
{
	struct carp_softc *sc;
	__u64 tmp_counter;
	bool multicast = false;

	CARPSTATS_INC(carps_ipackets);

	if (!carp_allow) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	/* Find matching CARP instance by interface + vhid */
	CARP_FOREACH_SC(sc) {
		if (sc->sc_carpdev == skb->dev &&
		    sc->sc_vhid == ch->carp_vhid)
			goto found;
	}

	CARPSTATS_INC(carps_badvhid);
	kfree_skb(skb);
	return NET_RX_DROP;

found:
	CARP_LOCK(sc);

	/* Verify the CARP version (mirrors FreeBSD) */
	if (ch->carp_version != CARP_VERSION) {
		CARPSTATS_INC(carps_badver);
		CARP_DEBUG("%s: invalid version %d\n",
			   __func__, ch->carp_version);
		goto out;
	}

	/* Check multicast flag */
	multicast = carp_is_multicast_v4(&sc->sc_carpaddr);

	/* Verify TTL = 255 (mirrors FreeBSD) */
	if (multicast && ttl != CARP_DFLTTL) {
		CARPSTATS_INC(carps_badttl);
		CARP_DEBUG("%s: received ttl %d != 255\n", __func__, ttl);
		goto out;
	}

	/* Verify HMAC (mirrors FreeBSD carp_hmac_verify) */
	if (carp_hmac_verify(sc, ch->carp_counter, ch->carp_md)) {
		CARPSTATS_INC(carps_badauth);
		CARP_DEBUG("%s: incorrect hash for VHID %u\n",
			   __func__, sc->sc_vhid);
		goto out;
	}

	/* Extract counter (mirrors FreeBSD) */
	tmp_counter = (__u64)ntohl(ch->carp_counter[0]) << 32;
	tmp_counter += ntohl(ch->carp_counter[1]);

	sc->sc_init_counter = 0;
	sc->sc_counter = tmp_counter;

	/*
	 * State machine (mirrors FreeBSD carp_input_c switch)
	 */
	switch (sc->sc_state) {
	case INIT:
		break;
	case MASTER:
		/*
		 * If we receive an advertisement from a master who's going to
		 * be more frequent than us, go into BACKUP state.
		 */
		if (ch->carp_advbase <= sc->sc_advbase) {
			del_timer(&sc->sc_ad_tmo);
			sc->sc_state = BACKUP;
			CARP_DEBUG("%s: VHID %u -> BACKUP\n",
				   __func__, sc->sc_vhid);

			/* Start master down timer (3 * advbase) */
			mod_timer(&sc->sc_md_tmo,
				  jiffies + 3 * sc->sc_advbase * HZ);
		}
		break;
	case BACKUP:
		/*
		 * If we're pre-empting masters who advertise slower than us,
		 * and this one claims to be slower, treat him as down.
		 * (mirrors FreeBSD carp_preempt logic)
		 */
		if (carp_preempt && ch->carp_advbase > sc->sc_advbase) {
			del_timer(&sc->sc_md_tmo);
			sc->sc_state = MASTER;
			CARP_DEBUG("%s: VHID %u -> MASTER (preempt)\n",
				   __func__, sc->sc_vhid);
			carp_send_ad_locked(sc);
			break;
		}

		/*
		 * If the master is going to advertise at such a low frequency
		 * that he's guaranteed to time out, treat him as timed out.
		 */
		if ((int)(ch->carp_advbase) * 3 <= sc->sc_advbase) {
			del_timer(&sc->sc_md_tmo);
			sc->sc_state = MASTER;
			CARP_DEBUG("%s: VHID %u -> MASTER (timeout)\n",
				   __func__, sc->sc_vhid);
			carp_send_ad_locked(sc);
			break;
		}

		/* Reset master down timer */
		mod_timer(&sc->sc_md_tmo,
			  jiffies + ch->carp_advbase * 3 * HZ);
		break;
	}

out:
	CARP_UNLOCK(sc);
	kfree_skb(skb);
	return NET_RX_SUCCESS;
}

/* IPv4 input handler (mirrors FreeBSD carp_input) */
static int carp_input(struct sk_buff *skb, struct net_device *dev,
		      struct packet_type *pt, struct net_device *orig_dev)
{
	struct iphdr *iph;
	struct carp_header *ch;
	int iplen;

	if (!pskb_may_pull(skb, sizeof(struct iphdr) + sizeof(struct carp_header)))
		return NET_RX_DROP;

	iph = ip_hdr(skb);

	/* Only handle CARP protocol packets */
	if (iph->protocol != IPPROTO_CARP)
		return NET_RX_DROP;

	iplen = iph->ihl * 4;

	ch = (struct carp_header *)((char *)iph + iplen);

	return carp_input_c(skb, ch, AF_INET, iph->ttl);
}

/* Protocol handler registration - match all IP packets, filter in handler */
static struct packet_type carp_packet_type __read_mostly = {
	.type = htons(ETH_P_IP),
	.func = carp_input,
};

/* ================================================================
 * Timer callbacks
 * ================================================================ */

/* Master down timer (mirrors FreeBSD carp_master_down_locked) */
static void carp_master_down(struct timer_list *t)
{
	struct carp_softc *sc = from_timer(sc, t, sc_md_tmo);

	CARP_LOCK(sc);
	if (sc->sc_state == BACKUP) {
		CARP_DEBUG("%s: VHID %u -> MASTER (master down)\n",
			   __func__, sc->sc_vhid);
		sc->sc_state = MASTER;
		carp_send_ad_locked(sc);
	}
	CARP_UNLOCK(sc);
}

/* ================================================================
 * Interface management
 * ================================================================ */

/*
 * Create a CARP instance on the given interface.
 * Mirrors FreeBSD carp_alloc + carp_ioctl_set.
 */
static struct carp_softc *carp_alloc(struct net_device *ifp, int vhid)
{
	struct carp_softc *sc;

	sc = kzalloc(sizeof(*sc), GFP_KERNEL);
	if (!sc)
		return NULL;

	sc->sc_carpdev = ifp;
	sc->sc_advbase = CARP_DFLTINTV;
	sc->sc_vhid = vhid;
	sc->sc_init_counter = 1;
	sc->sc_state = INIT;

	/* Default CARP multicast addresses (mirrors FreeBSD) */
	sc->sc_carpaddr.s_addr = htonl(INADDR_CARP_GROUP);
	/* IPv6: ff02::12 */
	sc->sc_carpaddr6.s6_addr[0]  = 0xff;
	sc->sc_carpaddr6.s6_addr[1]  = 0x02;
	sc->sc_carpaddr6.s6_addr[15] = 0x12;

	/* Virtual MAC address (mirrors FreeBSD) */
	sc->sc_mac[0] = 0x00;
	sc->sc_mac[1] = 0x00;
	sc->sc_mac[2] = 0x5e;
	sc->sc_mac[3] = 0x00;
	sc->sc_mac[4] = 0x01;
	sc->sc_mac[5] = (__u8)vhid;

	CARP_LOCK_INIT(sc);

	/* Initialize timers (mirrors FreeBSD callout_init_mtx) */
	timer_setup(&sc->sc_ad_tmo, carp_send_ad, 0);
	timer_setup(&sc->sc_md_tmo, carp_master_down, 0);
	timer_setup(&sc->sc_md6_tmo, carp_master_down, 0);

	/* Add to global list (mirrors FreeBSD LIST_INSERT_HEAD) */
	spin_lock_bh(&carp_mtx);
	list_add(&sc->sc_list, &carp_list);
	spin_unlock_bh(&carp_mtx);

	return sc;
}

/*
 * Destroy a CARP instance.
 * Mirrors FreeBSD carp_destroy.
 */
static void carp_destroy(struct carp_softc *sc)
{
	/* Stop all timers (mirrors FreeBSD callout_drain) */
	del_timer_sync(&sc->sc_ad_tmo);
	del_timer_sync(&sc->sc_md_tmo);
	del_timer_sync(&sc->sc_md6_tmo);

	/* Remove from global list (mirrors FreeBSD LIST_REMOVE) */
	spin_lock_bh(&carp_mtx);
	list_del(&sc->sc_list);
	spin_unlock_bh(&carp_mtx);

	carp_hmac_free(sc);
	kfree(sc);
}

/*
 * SIOCSVH handler (mirrors FreeBSD carp_ioctl_set).
 */
static int carp_ioctl_set(struct net_device *ifp, struct carpreq *carpr)
{
	struct carp_softc *sc;

	if (carpr->carpr_vhid <= 0 || carpr->carpr_vhid > CARP_MAXVHID ||
	    carpr->carpr_advbase < 0 || carpr->carpr_advskew < 0)
		return -EINVAL;

	/* Find existing softc for this vhid */
	CARP_FOREACH_SC(sc) {
		if (sc->sc_carpdev == ifp && sc->sc_vhid == carpr->carpr_vhid)
			break;
	}

	if (!sc || &sc->sc_list == carp_list.next) {
		/* Not found, allocate new (mirrors FreeBSD carp_alloc) */
		sc = carp_alloc(ifp, carpr->carpr_vhid);
		if (!sc)
			return -ENOMEM;
	}

	CARP_LOCK(sc);

	if (carpr->carpr_advbase > 0) {
		if (carpr->carpr_advbase > 255 ||
		    carpr->carpr_advbase < CARP_DFLTINTV) {
			CARP_UNLOCK(sc);
			return -EINVAL;
		}
		sc->sc_advbase = carpr->carpr_advbase;
	}

	if (carpr->carpr_advskew >= 0 && carpr->carpr_advskew <= CARP_MAXSKEW)
		sc->sc_advskew = carpr->carpr_advskew;

	if (carpr->carpr_key[0] != '\0') {
		memcpy(sc->sc_key, carpr->carpr_key, CARP_KEY_LEN);
		carp_hmac_prepare(sc);
	}

	/* State transition (mirrors FreeBSD) */
	if (sc->sc_state != INIT &&
	    carpr->carpr_state != (int)sc->sc_state) {
		switch (carpr->carpr_state) {
		case BACKUP:
			del_timer(&sc->sc_ad_tmo);
			sc->sc_state = BACKUP;
			CARP_DEBUG("%s: VHID %u -> BACKUP (user)\n",
				   __func__, sc->sc_vhid);
			/* Start master down timer */
			mod_timer(&sc->sc_md_tmo,
				  jiffies + 3 * sc->sc_advbase * HZ);
			break;
		case MASTER:
			sc->sc_state = MASTER;
			CARP_DEBUG("%s: VHID %u -> MASTER (user)\n",
				   __func__, sc->sc_vhid);
			carp_send_ad_locked(sc);
			break;
		default:
			break;
		}
	}

	CARP_UNLOCK(sc);
	return 0;
}

/*
 * SIOCGVH handler (mirrors FreeBSD carp_ioctl_get / carp_carprcp).
 */
static int carp_ioctl_get(struct net_device *ifp, struct carpreq *carpr)
{
	struct carp_softc *sc;

	if (carpr->carpr_vhid < 0 || carpr->carpr_vhid > CARP_MAXVHID)
		return -EINVAL;

	CARP_FOREACH_SC(sc) {
		if (sc->sc_carpdev == ifp && sc->sc_vhid == carpr->carpr_vhid) {
			CARP_LOCK(sc);
			carpr->carpr_state = sc->sc_state;
			carpr->carpr_vhid = sc->sc_vhid;
			carpr->carpr_advbase = sc->sc_advbase;
			carpr->carpr_advskew = sc->sc_advskew;
			memcpy(carpr->carpr_key, sc->sc_key, CARP_KEY_LEN);
			CARP_UNLOCK(sc);
			return 0;
		}
	}

	return -ENOENT;
}

/* ================================================================
 * Module init/exit
 * ================================================================ */

static int __init carp_init(void)
{
	CARP_LOG("CARP module loading (based on FreeBSD implementation)");
	dev_add_pack(&carp_packet_type);
	CARP_LOG("CARP module loaded");
	return 0;
}

static void __exit carp_exit(void)
{
	struct carp_softc *sc, *tmp;

	CARP_LOG("CARP module unloading");
	dev_remove_pack(&carp_packet_type);

	/* Destroy all instances (mirrors FreeBSD module unload) */
	CARP_FOREACH_SC(sc) {
		tmp = list_next_entry(sc, sc_list);
		carp_destroy(sc);
	}

	CARP_LOG("CARP module unloaded");
}

module_init(carp_init);
module_exit(carp_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Based on FreeBSD CARP implementation by Michael Shalayeff, Ryan McBride, Gleb Smirnoff");
MODULE_DESCRIPTION("Common Address Redundancy Protocol (CARP) for Linux");
MODULE_VERSION("1.0.0");
