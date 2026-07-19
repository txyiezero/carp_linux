/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * CARP advertisement sending, demotion, source address selection for Linux.
 */
#include "carp_internal.h"

/*
 * Send error demotion: track consecutive send failures.
 * 3 failures -> raise advskew (demote), let other nodes take over.
 * 3 successes -> lower advskew (undemote).
 */
void carp_send_ad_error(struct carp_softc *sc, int error)
{
	if (error) {
		if (sc->sc_sendad_errors < INT_MAX)
			sc->sc_sendad_errors++;
		if (sc->sc_sendad_errors >= CARP_SENDAD_MAX_ERRORS) {
			char msg[64];
			snprintf(msg, sizeof(msg), "send error %d on %s",
				 error, sc->sc_dev->name);
			carp_demote_adj(carp_senderr_adj, msg);
		}
		sc->sc_sendad_success = 0;
	} else if (sc->sc_sendad_errors > 0) {
		if (++sc->sc_sendad_success >= CARP_SENDAD_MIN_SUCCESS) {
			if (sc->sc_sendad_errors >= CARP_SENDAD_MAX_ERRORS) {
				char msg[64];
				snprintf(msg, sizeof(msg), "send ok on %s",
					 sc->sc_dev->name);
				carp_demote_adj(-carp_senderr_adj, msg);
			}
			sc->sc_sendad_errors = 0;
		}
	}
}

/*
 * Deferred work: re-send advertisements for all MASTER interfaces.
 * FreeBSD: carp_send_ad_all() via taskqueue_swi
 */
void carp_sendall_work_func(struct work_struct *work)
{
	struct carp_softc *sc;

	rcu_read_lock();
	list_for_each_entry_rcu(sc, &carp_if_list, sc_global) {
		if (sc->sc_state == CARP_STATE_MASTER)
			carp_send_ad_locked(sc);
	}
	rcu_read_unlock();
}

/*
 * Adjust global demotion factor and re-send all advertisements.
 */
void carp_demote_adj(int adj, const char *reason)
{
	carp_demotion += adj;
	if (carp_demotion > CARP_MAXSKEW)
		carp_demotion = CARP_MAXSKEW;
	else if (carp_demotion < 0)
		carp_demotion = 0;

	pr_info("carp: demoted by %d to %d (%s)\n",
		adj, carp_demotion, reason);

	/* Schedule deferred re-send */
	schedule_work(&carp_sendall_work);
}

/*
 * Prepare advertisement header: set counter and compute HMAC.
 */
void carp_prepare_ad(struct carp_softc *sc, struct carp_header *ch,
		     u32 counter[2])
{
	if (sc->sc_init_counter) {
		get_random_bytes(&sc->sc_counter, sizeof(sc->sc_counter));
	} else {
		sc->sc_counter++;
	}

	counter[0] = htonl((sc->sc_counter >> 32) & 0xffffffff);
	counter[1] = htonl(sc->sc_counter & 0xffffffff);

	carp_hmac_generate(sc, counter, ch->carp_md);
}

/*
 * Build and send a CARP advertisement (IPv4).
 */
static void carp_send_ad_v4(struct carp_softc *sc)
{
	struct sk_buff *skb;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct carp_header *ch;
	int total_len, hlen;
	__be16 id;

	/* Total: Ethernet + IP + CARP */
	total_len = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct carp_header);

	skb = alloc_skb(total_len + LL_RESERVED_SPACE(sc->sc_dev), GFP_ATOMIC);
	if (!skb) {
		CARPSTATS_INC(carps_onomem);
		return;
	}

	skb_reserve(skb, LL_RESERVED_SPACE(sc->sc_dev));
	skb->dev = sc->sc_dev;
	skb->protocol = htons(ETH_P_IP);
	skb->pkt_type = PACKET_HOST;
	skb->ip_summed = CHECKSUM_NONE;

	/* Push Ethernet header with virtual MAC as source */
	skb_push(skb, ETH_HLEN);
	skb_reset_mac_header(skb);
	eth = eth_hdr(skb);
	eth->h_proto = htons(ETH_P_IP);
	memcpy(eth->h_dest, sc->sc_lladdr, ETH_ALEN);
	eth->h_dest[5] = 0x12;  /* CARP group MAC: 01:00:5e:00:00:12 */
	memcpy(eth->h_source, sc->sc_lladdr, ETH_ALEN);

	/* Push IP header */
	skb_push(skb, sizeof(struct iphdr));
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);

	iph->version = 4;
	iph->ihl = 5;
	iph->tos = (carp_dscp << 2) & 0xFC;
	hlen = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct carp_header);
	iph->tot_len = htons(hlen - ETH_HLEN);
	get_random_bytes(&id, 2);
	iph->id = id;
	iph->frag_off = htons(IP_DF);
	iph->ttl = CARP_DFLTTL;
	iph->protocol = IPPROTO_CARP;

	/* Set source address from best local address */
	{
		struct in_ifaddr *best = carp_best_ifa4(sc->sc_dev);
		if (best) {
			iph->saddr = best->ifa_local;
			in_dev_put(best->ifa_dev);
		}
	}

	iph->daddr = sc->sc_carpaddr.s_addr;

	/* Push CARP header */
	skb_push(skb, sizeof(struct carp_header));
	ch = (struct carp_header *)skb->data;

	memset(ch, 0, sizeof(*ch));
	ch->carp_version = CARP_VERSION;
	ch->carp_type = CARP_ADVERTISEMENT;
	ch->carp_vhid = sc->sc_vhid;
	ch->carp_advbase = sc->sc_advbase;
	ch->carp_advskew = DEMOTE_ADVSKEW(sc);
	ch->carp_authlen = 7;
	ch->carp_pad1 = 0;
	ch->carp_cksum = 0;

	carp_prepare_ad(sc, ch, ch->carp_counter);

	/* Compute IP checksum */
	iph->check = 0;
	iph->check = ip_fast_csum((u8 *)iph, iph->ihl);

	/* Compute CARP checksum */
	{
		__sum16 csum;
		csum = csum_partial(skb->data + ETH_HLEN + sizeof(struct iphdr),
				     sizeof(struct carp_header), 0);
		ch->carp_cksum = csum_fold(csum);
	}

	CARPSTATS_INC(carps_opackets);

	/* Send directly via dev_queue_xmit */
	carp_send_ad_error(sc, dev_queue_xmit(skb));
}

/*
 * Build and send a CARP advertisement (IPv6).
 */
static void carp_send_ad_v6(struct carp_softc *sc)
{
	struct sk_buff *skb;
	struct ethhdr *eth;
	struct ipv6hdr *ip6h;
	struct carp_header *ch;
	int total_len;

	/* Total: Ethernet + IPv6 + CARP */
	total_len = ETH_HLEN + sizeof(struct ipv6hdr) + sizeof(struct carp_header);

	skb = alloc_skb(total_len + LL_RESERVED_SPACE(sc->sc_dev), GFP_ATOMIC);
	if (!skb) {
		CARPSTATS_INC(carps_onomem);
		return;
	}

	skb_reserve(skb, LL_RESERVED_SPACE(sc->sc_dev));
	skb->dev = sc->sc_dev;
	skb->protocol = htons(ETH_P_IPV6);
	skb->pkt_type = PACKET_HOST;
	skb->ip_summed = CHECKSUM_NONE;

	/* Push Ethernet header with virtual MAC as source */
	skb_push(skb, ETH_HLEN);
	skb_reset_mac_header(skb);
	eth = eth_hdr(skb);
	eth->h_proto = htons(ETH_P_IPV6);
	memcpy(eth->h_dest, sc->sc_lladdr, ETH_ALEN);
	eth->h_dest[5] = 0x12;
	memcpy(eth->h_source, sc->sc_lladdr, ETH_ALEN);

	/* Push IPv6 header */
	skb_push(skb, sizeof(struct ipv6hdr));
	skb_reset_network_header(skb);
	ip6h = ipv6_hdr(skb);

	memset(ip6h, 0, sizeof(*ip6h));
	ip6h->version = 6;
	ip6h->payload_len = htons(sizeof(struct carp_header));
	ip6h->nexthdr = IPPROTO_CARP;
	ip6h->hop_limit = CARP_DFLTTL;

	/* Set source address from best local address */
	{
		struct inet6_ifaddr *best6 = carp_best_ifa6(sc->sc_dev);
		if (best6) {
			ip6h->saddr = best6->addr;
			in6_dev_put(best6->idev);
		}
	}

	/* Set CARP multicast destination */
	memcpy(&ip6h->daddr, &sc->sc_carpaddr6, sizeof(ip6h->daddr));

	/* Push CARP header */
	skb_push(skb, sizeof(struct carp_header));
	ch = (struct carp_header *)skb->data;

	memset(ch, 0, sizeof(*ch));
	ch->carp_version = CARP_VERSION;
	ch->carp_type = CARP_ADVERTISEMENT;
	ch->carp_vhid = sc->sc_vhid;
	ch->carp_advbase = sc->sc_advbase;
	ch->carp_advskew = DEMOTE_ADVSKEW(sc);
	ch->carp_authlen = 7;
	ch->carp_pad1 = 0;
	ch->carp_cksum = 0;

	carp_prepare_ad(sc, ch, ch->carp_counter);

	/* Compute checksum */
	ch->carp_cksum = csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
					 sizeof(struct carp_header),
					 IPPROTO_CARP, 0);

	CARPSTATS_INC(carps_opackets6);

	/* Send directly via dev_queue_xmit */
	carp_send_ad_error(sc, dev_queue_xmit(skb));
}

/*
 * Send CARP advertisement (called from timer context).
 */
void carp_send_ad_locked(struct carp_softc *sc)
{
	struct timespec64 tv;

	/* Send IPv4 ad if we have IPv4 addresses */
	if (sc->sc_naddrs > 0)
		carp_send_ad_v4(sc);

	/* Send IPv6 ad if we have IPv6 addresses */
	if (sc->sc_naddrs6 > 0)
		carp_send_ad_v6(sc);

	/* Schedule next advertisement */
	tv.tv_sec = sc->sc_advbase;
	tv.tv_nsec = (long)DEMOTE_ADVSKEW(sc) * 1000000000L / 256;

	mod_timer(&sc->sc_ad_timer, jiffies + timespec64_to_jiffies(&tv));
}

/* Timer callback: send periodic advertisement. */
void carp_send_ad_timer(struct timer_list *t)
{
	struct carp_softc *sc = from_timer(sc, t, sc_ad_timer);

	carp_send_ad_locked(sc);
}

/*
 * Master down: promote to MASTER.
 */
void carp_master_down_locked(struct carp_softc *sc, const char *reason)
{
	switch (sc->sc_state) {
	case CARP_STATE_BACKUP:
		carp_set_state(sc, CARP_STATE_MASTER, reason);
		carp_send_ad_locked(sc);
		if (sc->sc_naddrs > 0)
			carp_send_arp(sc);
		if (sc->sc_naddrs6 > 0)
			carp_send_na(sc);
		carp_setrun(sc, 0);
		break;
	default:
		break;
	}
}

void carp_master_down_timer(struct timer_list *t)
{
	struct carp_softc *sc = from_timer(sc, t, sc_md_timer);

	if (sc->sc_state == CARP_STATE_BACKUP)
		carp_master_down_locked(sc, "master timed out");
}

void carp_master_down6_timer(struct timer_list *t)
{
	struct carp_softc *sc = from_timer(sc, t, sc_md6_timer);

	if (sc->sc_state == CARP_STATE_BACKUP)
		carp_master_down_locked(sc, "master timed out (IPv6)");
}

/*
 * Set advertisement/master-down timers.
 */
void carp_setrun(struct carp_softc *sc, int af)
{
	struct timespec64 tv;

	if (!netif_running(sc->sc_dev) ||
	    !netif_carrier_ok(sc->sc_dev) ||
	    (sc->sc_naddrs == 0 && sc->sc_naddrs6 == 0) ||
	    !carp_allow)
		return;

	switch (sc->sc_state) {
	case CARP_STATE_INIT:
		carp_set_state(sc, CARP_STATE_BACKUP, "initialization complete");
		carp_setrun(sc, 0);
		break;
	case CARP_STATE_BACKUP:
		del_timer_sync(&sc->sc_ad_timer);
		tv.tv_sec = 3 * sc->sc_advbase;
		tv.tv_nsec = (long)sc->sc_advskew * 1000000000L / 256;

		if (af == AF_INET && sc->sc_naddrs > 0)
			mod_timer(&sc->sc_md_timer, jiffies + timespec64_to_jiffies(&tv));
		else if (af == AF_INET6 && sc->sc_naddrs6 > 0)
			mod_timer(&sc->sc_md6_timer, jiffies + timespec64_to_jiffies(&tv));
		else if (af == 0) {
			if (sc->sc_naddrs > 0)
				mod_timer(&sc->sc_md_timer, jiffies + timespec64_to_jiffies(&tv));
			if (sc->sc_naddrs6 > 0)
				mod_timer(&sc->sc_md6_timer, jiffies + timespec64_to_jiffies(&tv));
		}
		break;
	case CARP_STATE_MASTER:
		tv.tv_sec = sc->sc_advbase;
		tv.tv_nsec = (long)DEMOTE_ADVSKEW(sc) * 1000000000L / 256;
		mod_timer(&sc->sc_ad_timer, jiffies + timespec64_to_jiffies(&tv));
		break;
	}
}

/*
 * Send gratuitous ARP when becoming MASTER.
 */
void carp_send_arp(struct carp_softc *sc)
{
	int i;

	for (i = 0; i < sc->sc_naddrs; i++) {
		if (!sc->sc_ifas4[i])
			continue;
		arp_send(ARPOP_REPLY, ETH_P_ARP,
			 sc->sc_ifas4[i]->ifa_local,
			 sc->sc_dev,
			 sc->sc_ifas4[i]->ifa_local,
			 sc->sc_lladdr,
			 NULL,
			 NULL);
	}
}

/*
 * Send gratuitous NA when becoming MASTER (IPv6).
 */
void carp_send_na(struct carp_softc *sc)
{
	int i;

	for (i = 0; i < sc->sc_naddrs6; i++) {
		if (!sc->sc_ifas6[i])
			continue;
		ndisc_send_na(sc->sc_dev, &in6addr_any,
			      &sc->sc_ifas6[i]->addr,
			      false,  /* router */
			      false,  /* solicited */
			      true,   /* override */
			      true);  /* inc_opt */
	}
}

/*
 * Find the best IPv4 address on an interface.
 */
struct in_ifaddr *carp_best_ifa4(struct net_device *dev)
{
	struct in_device *in_dev;
	struct in_ifaddr *ifa, *best = NULL;

	in_dev = __in_dev_get_rtnl(dev);
	if (!in_dev)
		return NULL;

	in_dev_for_each_ifa_rcu(ifa, in_dev) {
		if (ifa->ifa_local == 0)
			continue;
		if (!best)
			best = ifa;
		else if ((ifa->ifa_flags & IFA_F_PERMANENT) &&
			 !(best->ifa_flags & IFA_F_PERMANENT))
			best = ifa;
	}

	if (best)
		in_dev_hold(best->ifa_dev);
	return best;
}

/*
 * Find the best IPv6 address on an interface.
 */
struct inet6_ifaddr *carp_best_ifa6(struct net_device *dev)
{
	struct inet6_dev *idev;
	struct inet6_ifaddr *ifa6, *best = NULL;

	idev = __in6_dev_get(dev);
	if (!idev)
		return NULL;

	list_for_each_entry_rcu(ifa6, &idev->addr_list, if_list) {
		if (ipv6_addr_any(&ifa6->addr))
			continue;
		if (!best)
			best = ifa6;
		else if ((ifa6->flags & IFA_F_PERMANENT) &&
			 !(best->flags & IFA_F_PERMANENT))
			best = ifa6;
	}

	if (best)
		in6_dev_hold(best->idev);
	return best;
}
