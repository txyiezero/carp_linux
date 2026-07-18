/* SPDX-License-Identifier: BSD-2-Clause */
#include "carp_internal.h"
#include <net/netns/generic.h>

/* Forward declarations */
static struct genl_family carp_genl_family;
static struct nf_hook_ops *carp_nf_ops;

/*
 * Join/leave CARP multicast groups.
 * FreeBSD: carp_multicast_setup() / carp_multicast_cleanup()
 */
void carp_multicast_setup(struct carp_softc *sc)
{
	/* IPv4: join 224.0.0.18 */
	if (sc->sc_naddrs > 0) {
		u8 addr[6] = { 0xe0, 0x00, 0x00, 0x12, 0, 0 };
		dev_mc_add(sc->sc_dev, addr);
	}

	/* IPv6: join ff02::12 */
	if (sc->sc_naddrs6 > 0) {
		u8 addr6[6] = { 0xff, 0x02, 0, 0, 0, 0x12 };
		dev_mc_add(sc->sc_dev, addr6);
	}
}

void carp_multicast_cleanup(struct carp_softc *sc)
{
	if (sc->sc_naddrs == 0 && sc->sc_naddrs6 == 0) {
		u8 addr[6] = { 0xe0, 0x00, 0x00, 0x12, 0, 0 };
		u8 addr6[6] = { 0xff, 0x02, 0, 0, 0, 0x12 };
		dev_mc_del(sc->sc_dev, addr);
		dev_mc_del(sc->sc_dev, addr6);
	}
}

/*
 * ARP/NDP/Bridge hooks for CARP address resolution.
 * FreeBSD: carp_iamatch, carp_iamatch6, carp_macmatch6, carp_forus
 */

/*
 * Check if an IPv4 address belongs to a CARP MASTER interface.
 * FreeBSD: carp_iamatch() — called from if_ether.c for ARP replies
 */
int carp_iamatch4(struct net_device *dev, __be32 addr)
{
	struct carp_softc *sc;
	int i;

	rcu_read_lock();
	list_for_each_entry_rcu(sc, &carp_if_list, sc_global) {
		if (sc->sc_dev != dev || sc->sc_state != CARP_STATE_MASTER)
			continue;
		for (i = 0; i < sc->sc_naddrs; i++) {
			if (sc->sc_ifas4[i] &&
			    sc->sc_ifas4[i]->ifa_local == addr) {
				rcu_read_unlock();
				return 1;
			}
		}
	}
	rcu_read_unlock();
	return 0;
}
EXPORT_SYMBOL(carp_iamatch4);

/*
 * Check if an IPv6 address belongs to a CARP MASTER interface.
 * FreeBSD: carp_iamatch6() — called from nd6_nbr.c for NDP replies
 */
struct in6_ifaddr *carp_iamatch6(struct net_device *dev,
				     const struct in6_addr *addr)
{
	struct carp_softc *sc;
	int i;

	rcu_read_lock();
	list_for_each_entry_rcu(sc, &carp_if_list, sc_global) {
		if (sc->sc_dev != dev || sc->sc_state != CARP_STATE_MASTER)
			continue;
		for (i = 0; i < sc->sc_naddrs6; i++) {
			if (sc->sc_ifas6[i] &&
			    memcmp(&sc->sc_ifas6[i]->addr, addr, 16) == 0) {
				in6_dev_hold(sc->sc_ifas6[i]->idev);
				rcu_read_unlock();
				return sc->sc_ifas6[i];
			}
		}
	}
	rcu_read_unlock();
	return NULL;
}
EXPORT_SYMBOL(carp_iamatch6);

/*
 * Get the virtual MAC for a CARP address.
 * FreeBSD: carp_macmatch6() — called from nd6_nbr.c
 */
u8 *carp_macmatch6(struct net_device *dev, const struct in6_addr *addr)
{
	struct carp_softc *sc;
	int i;

	rcu_read_lock();
	list_for_each_entry_rcu(sc, &carp_if_list, sc_global) {
		if (sc->sc_dev != dev || sc->sc_state != CARP_STATE_MASTER)
			continue;
		for (i = 0; i < sc->sc_naddrs6; i++) {
			if (sc->sc_ifas6[i] &&
			    memcmp(&sc->sc_ifas6[i]->addr, addr, 16) == 0) {
				rcu_read_unlock();
				return sc->sc_lladdr;
			}
		}
	}
	rcu_read_unlock();
	return NULL;
}
EXPORT_SYMBOL(carp_macmatch6);

/*
 * Check if a destination MAC belongs to a CARP MASTER on this bridge.
 * FreeBSD: carp_forus() — called from if_bridge.c
 */
int carp_forus(struct net_device *dev, const u8 *dhost)
{
	struct carp_softc *sc;

	/* CARP virtual MACs are 00:00:5e:00:01:XX */
	if (dhost[0] || dhost[1] || dhost[2] != 0x5e ||
	    dhost[3] || dhost[4] != 1)
		return 0;

	rcu_read_lock();
	list_for_each_entry_rcu(sc, &carp_if_list, sc_global) {
		if (sc->sc_dev == dev &&
		    sc->sc_state == CARP_STATE_MASTER &&
		    memcmp(dhost, sc->sc_lladdr, ETH_ALEN) == 0) {
			rcu_read_unlock();
			return 1;
		}
	}
	rcu_read_unlock();
	return 0;
}
EXPORT_SYMBOL(carp_forus);

/*
 * Query if an interface is CARP MASTER.
 * FreeBSD: carp_master() — called from if.c
 */
int carp_is_master(struct net_device *dev, int vhid)
{
	struct carp_softc *sc;

	rcu_read_lock();
	list_for_each_entry_rcu(sc, &carp_if_list, sc_global) {
		if (sc->sc_dev == dev &&
		    (vhid == 0 || sc->sc_vhid == vhid) &&
		    sc->sc_state == CARP_STATE_MASTER) {
			rcu_read_unlock();
			return 1;
		}
	}
	rcu_read_unlock();
	return 0;
}
EXPORT_SYMBOL(carp_is_master);

/*
 * Get VHID for a given address.
 * FreeBSD: carp_get_vhid() — called from rtsock.c
 */
int carp_get_vhid(struct net_device *dev, __be32 addr)
{
	struct carp_softc *sc;
	int i;

	rcu_read_lock();
	list_for_each_entry_rcu(sc, &carp_if_list, sc_global) {
		if (sc->sc_dev != dev)
			continue;
		for (i = 0; i < sc->sc_naddrs; i++) {
			if (sc->sc_ifas4[i] &&
			    sc->sc_ifas4[i]->ifa_local == addr) {
				rcu_read_unlock();
				return sc->sc_vhid;
			}
		}
	}
	rcu_read_unlock();
	return 0;
}
EXPORT_SYMBOL(carp_get_vhid);

/*
 * Netfilter hook for regular traffic source MAC replacement.
 * FreeBSD: carp_output() — replaces source MAC for all traffic from virtual IP
 * Linux: NF_INET_POST_ROUTING hook checks if source is CARP address
 */
static struct nf_hook_ops *carp_nf_ops;

		}
	}
	rcu_read_unlock();

	return NF_ACCEPT;
}

static struct genl_family carp_genl_family;

/* Netlink GET handler */
static int carp_nl_get(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;
	u32 vhid = 0;
	const char *ifname = NULL;
	struct carp_softc *sc;
	struct net_device *dev;
	int ifindex = 0;

	if (info->attrs[CARP_NL_VHID])
		vhid = nla_get_u32(info->attrs[CARP_NL_VHID]);
	if (info->attrs[CARP_NL_IFINDEX])
		ifindex = nla_get_u32(info->attrs[CARP_NL_IFINDEX]);
	if (info->attrs[CARP_NL_IFNAME])
		ifname = nla_data(info->attrs[CARP_NL_IFNAME]);

	if (ifname) {
		dev = dev_get_by_name(genl_info_net(info), ifname);
		if (!dev)
			return -ENODEV;
	} else if (ifindex) {
		dev = dev_get_by_index(genl_info_net(info), ifindex);
		if (!dev)
			return -ENODEV;
	} else {
		return -EINVAL;
	}

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg) {
		dev_put(dev);
		return -ENOMEM;
	}

	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
			  &carp_genl_family, 0, CARP_NL_CMD_GET);
	if (!hdr) {
		nlmsg_free(msg);
		dev_put(dev);
		return -EMSGSIZE;
	}

	rcu_read_lock();
	sc = sc_lookup_vhid(dev, vhid);
	if (sc) {
		nla_put_u32(msg, CARP_NL_VHID, sc->sc_vhid);
		nla_put_u32(msg, CARP_NL_STATE, sc->sc_state);
		nla_put_s32(msg, CARP_NL_ADVBASE, sc->sc_advbase);
		nla_put_s32(msg, CARP_NL_ADVSKEW, sc->sc_advskew);
		nla_put(msg, CARP_NL_ADDR, sizeof(sc->sc_carpaddr),
			&sc->sc_carpaddr);
		nla_put(msg, CARP_NL_ADDR6, sizeof(sc->sc_carpaddr6),
			&sc->sc_carpaddr6);
		nla_put_string(msg, CARP_NL_IFNAME, dev->name);
	}
	rcu_read_unlock();

	dev_put(dev);
	genlmsg_end(msg, hdr);
	return genlmsg_reply(msg, info);
}

/* Netlink SET handler */
static int carp_nl_set(struct sk_buff *skb, struct genl_info *info)
{
	u32 vhid, state = CARP_STATE_INIT;
	s32 advbase = -1, advskew = -1;
	const char *ifname;
	struct net_device *dev;
	struct carp_softc *sc;

	if (!info->attrs[CARP_NL_VHID] || !info->attrs[CARP_NL_IFNAME])
		return -EINVAL;

	vhid = nla_get_u32(info->attrs[CARP_NL_VHID]);
	ifname = nla_data(info->attrs[CARP_NL_IFNAME]);

	if (vhid == 0 || vhid > CARP_MAXVHID)
		return -EINVAL;

	if (info->attrs[CARP_NL_STATE])
		state = nla_get_u32(info->attrs[CARP_NL_STATE]);
	if (info->attrs[CARP_NL_ADVBASE])
		advbase = nla_get_s32(info->attrs[CARP_NL_ADVBASE]);
	if (info->attrs[CARP_NL_ADVSKEW])
		advskew = nla_get_s32(info->attrs[CARP_NL_ADVSKEW]);

	dev = dev_get_by_name(genl_info_net(info), ifname);
	if (!dev)
		return -ENODEV;

	sc = sc_lookup_vhid(dev, vhid);
	if (!sc) {
		/* Create new softc */
		sc = carp_alloc(dev, vhid);
		if (!sc) {
			dev_put(dev);
			return -ENOMEM;
		}
	}

	if (advbase >= 0 && advbase <= 255)
		sc->sc_advbase = advbase;
	if (advskew >= 0 && advskew < 255)
		sc->sc_advskew = advskew;

	if (info->attrs[CARP_NL_KEY]) {
		int key_len = nla_len(info->attrs[CARP_NL_KEY]);
		if (key_len > 0 && key_len <= CARP_KEY_LEN) {
			memcpy(sc->sc_key, nla_data(info->attrs[CARP_NL_KEY]),
			       key_len);
			carp_hmac_prepare(sc);
		}
	}

	if (info->attrs[CARP_NL_ADDR])
		sc->sc_carpaddr = nla_get_in_addr(info->attrs[CARP_NL_ADDR]);
	if (info->attrs[CARP_NL_ADDR6])
		memcpy(&sc->sc_carpaddr6, nla_data(info->attrs[CARP_NL_ADDR6]),
		       sizeof(sc->sc_carpaddr6));

	if (state <= CARP_MAXSTATE && state != sc->sc_state) {
		switch (state) {
		case CARP_STATE_BACKUP:
			del_timer_sync(&sc->sc_ad_timer);
			carp_set_state(sc, CARP_STATE_BACKUP,
				       "user requested");
			carp_setrun(sc, 0);
			carp_delroute(sc);
			break;
		case CARP_STATE_MASTER:
			carp_master_down_locked(sc, "user requested");
			break;
		}
	}

	dev_put(dev);
	return 0;
}

static const struct nla_policy carp_nl_policy[CARP_NL_IFNAME + 1] = {
	[CARP_NL_VHID]    = { .type = NLA_U32 },
	[CARP_NL_STATE]   = { .type = NLA_U32 },
	[CARP_NL_ADVBASE] = { .type = NLA_S32 },
	[CARP_NL_ADVSKEW] = { .type = NLA_S32 },
	[CARP_NL_KEY]     = { .type = NLA_BINARY, .len = CARP_KEY_LEN },
	[CARP_NL_IFINDEX] = { .type = NLA_U32 },
	[CARP_NL_IFNAME]  = { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
};

static const struct genl_ops carp_nl_ops[] = {
	{
		.cmd = CARP_NL_CMD_GET,
		.doit = carp_nl_get,
		.policy = carp_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = CARP_NL_CMD_SET,
		.doit = carp_nl_set,
		.policy = carp_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
};

static struct genl_family carp_genl_family = {
	.name = CARP_NL_FAMILY_NAME,
	.version = 1,
	.maxattr = CARP_NL_IFNAME,
	.module = THIS_MODULE,
	.ops = carp_nl_ops,
	.n_ops = ARRAY_SIZE(carp_nl_ops),
};

/*
 * Module init/exit
 */
