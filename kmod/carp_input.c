/* SPDX-License-Identifier: BSD-2-Clause */
#include "carp_internal.h"

/* Forward declarations */
static int carp_source_is_self4(struct carp_softc *sc, struct iphdr *iph);
static int carp_source_is_self6(struct carp_softc *sc, struct ipv6hdr *ip6h);

/*
 * HMAC-SHA1 using Linux kernel crypto API.
 */
static struct crypto_shash *carp_tfm;

int carp_hmac_init(void)
{
	carp_tfm = crypto_alloc_shash("hmac(sha1)", 0, 0);
	if (IS_ERR(carp_tfm)) {
		pr_warn("hmac(sha1) not available, trying sha1\n");
		carp_tfm = crypto_alloc_shash("sha1", 0, 0);
		if (IS_ERR(carp_tfm)) {
			pr_err("Failed to allocate SHA1 transform\n");
			return PTR_ERR(carp_tfm);
		}
	}
	return 0;
}

void carp_hmac_fini(void)
{
	if (!IS_ERR(carp_tfm))
		crypto_free_shash(carp_tfm);
}


void carp_hmac_generate(struct carp_softc *sc, u32 counter[2], u8 md[20])
{
	SHASH_DESC_ON_STACK(desc, carp_tfm);
	u8 version = CARP_VERSION;
	u8 type = CARP_ADVERTISEMENT;
	u8 vhid = sc->sc_vhid & 0xff;
	int j, k;

	crypto_shash_setkey(carp_tfm, sc->sc_key, CARP_KEY_LEN);

	crypto_shash_init(desc);
	crypto_shash_update(desc, &version, 1);
	crypto_shash_update(desc, &type, 1);
	crypto_shash_update(desc, &vhid, 1);

	/* IPv4 addresses in sorted order */
	{
		__be32 sorted_addrs[256];
		int n = 0;
		for (j = 0; j < sc->sc_naddrs && n < 256; j++) {
			if (sc->sc_ifas4[j])
				sorted_addrs[n++] = sc->sc_ifas4[j]->ifa_local;
		}
		for (j = 1; j < n; j++) {
			struct in_addr tmp = sorted_addrs[j];
			k = j - 1;
			while (k >= 0 &&
			       ntohl(sorted_addrs[k].s_addr) > ntohl(tmp.s_addr)) {
				sorted_addrs[k + 1] = sorted_addrs[k];
				k--;
			}
			sorted_addrs[k + 1] = tmp;
		}
		for (j = 0; j < n; j++)
			crypto_shash_update(desc, (u8 *)&sorted_addrs[j], 4);
	}

	/* IPv6 addresses in sorted order */
	{
		struct in6_addr sorted_addrs6[256];
		int n = 0;
		for (j = 0; j < sc->sc_naddrs6 && n < 256; j++) {
			if (sc->sc_ifas6[j])
				sorted_addrs6[n++] = sc->sc_ifas6[j]->addr;
		}
		for (j = 1; j < n; j++) {
			struct in6_addr tmp = sorted_addrs6[j];
			k = j - 1;
			while (k >= 0 &&
			       memcmp(&sorted_addrs6[k], &tmp, 16) > 0) {
				sorted_addrs6[k + 1] = sorted_addrs6[k];
				k--;
			}
			sorted_addrs6[k + 1] = tmp;
		}
		for (j = 0; j < n; j++)
			crypto_shash_update(desc, (u8 *)&sorted_addrs6[j], 16);
	}

	crypto_shash_update(desc, (u8 *)counter, 8);
	crypto_shash_final(desc, md);

	shash_desc_zero(desc);
}

int carp_hmac_verify(struct carp_softc *sc, u32 counter[2], u8 md[20])
{
	u8 md2[20];

	carp_hmac_generate(sc, counter, md2);
	return memcmp(md, md2, 20) ? -EBADMSG : 0;
}

/*
 * Process incoming CARP packet (common for IPv4 and IPv6).
 */
/*
 * Detect packet loops (e.g. VMware ESX vswitch echoing our own packets).
 * FreeBSD: carp_source_is_self()
 */
static int carp_source_is_self4(struct carp_softc *sc, struct iphdr *iph)
{
	int i;

	for (i = 0; i < sc->sc_naddrs; i++) {
		if (sc->sc_ifas4[i] &&
		    sc->sc_ifas4[i]->ifa_local == iph->saddr)
			return 1;
	}
	return 0;
}

static int carp_source_is_self6(struct carp_softc *sc, struct ipv6hdr *ip6h)
{
	int i;

	for (i = 0; i < sc->sc_naddrs6; i++) {
		if (sc->sc_ifas6[i] &&
		    memcmp(&sc->sc_ifas6[i]->addr, &ip6h->saddr, 16) == 0)
			return 1;
	}
	return 0;
}

void carp_input_c(struct sk_buff *skb, struct carp_header *ch,
			 int af, int ttl)
{
	struct net_device *dev = skb->dev;
	struct carp_softc *sc;
	u64 tmp_counter;
	struct timespec64 sc_tv, ch_tv;
	bool multicast = false;

	rcu_read_lock();

	/* Verify VHID is valid on this interface */
	sc = sc_lookup_vhid(dev, ch->carp_vhid);
	if (!sc) {
		CARPSTATS_INC(carps_badvhid);
		goto out;
	}

	/* Verify CARP version */
	/* Loop detection: if VHID=0 and source is ourselves, drop */
	if (ch->carp_vhid == 0) {
		if (skb->protocol == htons(ETH_P_IP)) {
			struct iphdr *iph = ip_hdr(skb);
			if (carp_source_is_self4(sc, iph)) {
				CARPSTATS_INC(carps_badif);
				if (carp_log > 1)
					pr_debug("dropping looped packet on %s\n",
						 skb->dev->name);
				goto out;
			}
		} else if (skb->protocol == htons(ETH_P_IPV6)) {
			struct ipv6hdr *ip6h = ipv6_hdr(skb);
			if (carp_source_is_self6(sc, ip6h)) {
				CARPSTATS_INC(carps_badif);
				if (carp_log > 1)
					pr_debug("dropping looped packet on %s\n",
						 skb->dev->name);
				goto out;
			}
		}
	}

	/* verify the CARP version. */
	if (ch->carp_version != CARP_VERSION) {
		CARPSTATS_INC(carps_badver);
		if (carp_log > 1)
			pr_debug("invalid version %d on %s\n",
				 ch->carp_version, dev->name);
		goto out;
	}

	/* Verify TTL=255 for multicast */
	if (af == AF_INET)
		multicast = IN_MULTICAST(ntohl(sc->sc_carpaddr.s_addr));
	else
		multicast = ipv6_addr_is_multicast(&sc->sc_carpaddr6);

	if (multicast && ttl != CARP_DFLTTL) {
		CARPSTATS_INC(carps_badttl);
		if (carp_log > 1)
			pr_debug("received ttl %d != 255 on %s\n",
				 ttl, dev->name);
		goto out;
	}

	/* Verify HMAC */
	if (carp_hmac_verify(sc, ch->carp_counter, ch->carp_md)) {
		CARPSTATS_INC(carps_badauth);
		if (carp_log > 1)
			pr_debug("incorrect hash for VHID %u@%s\n",
				 sc->sc_vhid, dev->name);
		goto out;
	}

	/* Extract counter */
	tmp_counter = ntohl(ch->carp_counter[0]);
	tmp_counter = tmp_counter << 32;
	tmp_counter += ntohl(ch->carp_counter[1]);

	sc->sc_init_counter = 0;
	sc->sc_counter = tmp_counter;

	/* Calculate advertisement intervals */
	sc_tv.tv_sec = sc->sc_advbase;
	sc_tv.tv_nsec = (long)DEMOTE_ADVSKEW(sc) * 1000000000L / 256;
	ch_tv.tv_sec = ch->carp_advbase;
	ch_tv.tv_nsec = (long)ch->carp_advskew * 1000000000L / 256;

	/* State machine */
	switch (sc->sc_state) {
	case CARP_STATE_INIT:
		break;
	case CARP_STATE_MASTER:
		/* If we receive a more frequent advertisement, go to BACKUP */
		if (timespec64_compare(&sc_tv, &ch_tv) > 0 ||
		    timespec64_compare(&sc_tv, &ch_tv) == 0) {
			del_timer_sync(&sc->sc_ad_timer);
			carp_set_state(sc, CARP_STATE_BACKUP,
				       "more frequent advertisement received");
			carp_setrun(sc, 0);
		}
		break;
	case CARP_STATE_BACKUP:
		/* Preemption: if we advertise faster, treat slow master as down */
		if (carp_preempt && timespec64_compare(&sc_tv, &ch_tv) < 0) {
			if (carp_log > 1)
				pr_info("VHID %u@%s: preempting slower master\n",
					sc->sc_vhid, dev->name);
			carp_set_state(sc, CARP_STATE_MASTER,
				       "preempting a slower master");
			carp_send_ad_locked(sc);
			if (af == AF_INET)
				carp_send_arp(sc);
			if (af == AF_INET6)
				carp_send_na(sc);
			carp_setrun(sc, 0);
			break;
		}

		/* If master will time out, treat as down now */
		struct timespec64 timeout_tv;
		timeout_tv.tv_sec = sc->sc_advbase * 3;
		timeout_tv.tv_nsec = 0;
		if (timespec64_compare(&timeout_tv, &ch_tv) < 0) {
			if (carp_log > 1)
				pr_info("VHID %u@%s: master will time out\n",
					sc->sc_vhid, dev->name);
			carp_set_state(sc, CARP_STATE_MASTER,
				       "master will time out");
			carp_send_ad_locked(sc);
			if (af == AF_INET)
				carp_send_arp(sc);
			if (af == AF_INET6)
				carp_send_na(sc);
			carp_setrun(sc, 0);
			break;
		}

		/* Reset timer, wait for next advertisement */
		carp_setrun(sc, af);
		break;
	}

out:
	rcu_read_unlock();
	kfree_skb(skb);
}

/*
 * IPv4 CARP input handler.
 * Called from raw socket or protocol handler registration.
 */
int carp_input4(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct carp_header *ch;
	int iplen;

	if (!carp_allow) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	CARPSTATS_INC(carps_ipackets);

	if (!pskb_may_pull(skb, sizeof(*iph) + sizeof(*ch))) {
		CARPSTATS_INC(carps_badlen);
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	iph = ip_hdr(skb);
	iplen = iph->ihl * 4;

	if (iph->protocol != IPPROTO_CARP) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	ch = (struct carp_header *)(skb->data + iplen);

	/* Verify checksum */
	{
		__sum16 csum = ip_compute_csum(skb->data + iplen, skb->len - iplen);
		if (csum != 0) {
			CARPSTATS_INC(carps_badsum);
			kfree_skb(skb);
			return NET_RX_DROP;
		}
	}

	carp_input_c(skb, ch, AF_INET, iph->ttl);
	return NET_RX_DROP;
}

/*
 * IPv6 CARP input handler.
 */
int carp_input6(struct sk_buff *skb)
{
	struct ipv6hdr *ip6h;
	struct carp_header *ch;

	if (!carp_allow) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	CARPSTATS_INC(carps_ipackets6);

	if (!pskb_may_pull(skb, sizeof(*ip6h) + sizeof(*ch))) {
		CARPSTATS_INC(carps_badlen);
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	ip6h = ipv6_hdr(skb);
	if (ip6h->nexthdr != IPPROTO_CARP) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	/* Check if received on a CARP interface (FreeBSD: if_carp == NULL) */
	{
		struct carp_softc *sc;
		sc = sc_lookup_vhid(skb->dev, 0);
		if (!sc) {
			CARPSTATS_INC(carps_badif);
			kfree_skb(skb);
			return NET_RX_DROP;
		}
	}

	ch = (struct carp_header *)(skb->data + sizeof(*ip6h));

	/* Verify checksum */
	{
		__sum16 csum = csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
						skb->len - sizeof(*ip6h),
						IPPROTO_CARP, 0);
		if (csum != 0) {
			CARPSTATS_INC(carps_badsum);
			kfree_skb(skb);
			return NET_RX_DROP;
		}
	}

	carp_input_c(skb, ch, AF_INET6, ip6h->hop_limit);
	return NET_RX_DROP;
}

