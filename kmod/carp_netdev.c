/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * CARP network device integration for Linux.
 * Handles: protocol 112 registration, NF hook, device event notifications.
 */
#include "carp_internal.h"

/*
 * Protocol 112 handler registration.
 * CARP and VRRP both use IP protocol 112 but are different protocols.
 * We register our handler so the kernel delivers CARP packets to us.
 */
static const struct net_protocol carp_protocol = {
	.handler	= carp_input4,
	.no_policy	= 1,
};

#if IS_ENABLED(CONFIG_IPV6)
static const struct inet6_protocol carp6_protocol = {
	.handler	= carp_input6,
	.flags		= INET6_PROTO_NOPOLICY,
};
#endif

/*
 * Netfilter hook: replace source MAC for CARP traffic.
 * FreeBSD: carp_output() via if_output hook (L2)
 * Linux: NF_INET_POST_ROUTING hook (L3)
 */
static unsigned int carp_nf_hook(void *priv, struct sk_buff *skb,
				    const struct nf_hook_state *state)
{
	struct ethhdr *eth;
	struct carp_softc *sc;
	int i;

	if (!skb_mac_header_was_set(skb))
		return NF_ACCEPT;

	eth = eth_hdr(skb);

	rcu_read_lock();
	list_for_each_entry_rcu(sc, &carp_if_list, sc_global) {
		if (sc->sc_dev != skb->dev || sc->sc_state != CARP_STATE_MASTER)
			continue;

		/* Check if source IP matches a CARP address */
		if (skb->protocol == htons(ETH_P_IP)) {
			struct iphdr *iph = ip_hdr(skb);
			for (i = 0; i < sc->sc_naddrs; i++) {
				if (sc->sc_ifas4[i] &&
				    sc->sc_ifas4[i]->ifa_local == iph->saddr) {
					memcpy(eth->h_source, sc->sc_lladdr, ETH_ALEN);
					rcu_read_unlock();
					return NF_ACCEPT;
				}
			}
		} else if (skb->protocol == htons(ETH_P_IPV6)) {
			struct ipv6hdr *ip6h = ipv6_hdr(skb);
			for (i = 0; i < sc->sc_naddrs6; i++) {
				if (sc->sc_ifas6[i] &&
				    memcmp(&sc->sc_ifas6[i]->addr, &ip6h->saddr, 16) == 0) {
					memcpy(eth->h_source, sc->sc_lladdr, ETH_ALEN);
					rcu_read_unlock();
					return NF_ACCEPT;
				}
			}
		}
	}
	rcu_read_unlock();

	return NF_ACCEPT;
}

static struct nf_hook_ops *carp_nf_ops;

/*
 * Device event handler: react to interface up/down/link changes.
 * FreeBSD: carp_linkstate() via carp_linkstate_p hook
 * Linux: register_netdevice_notifier
 */
static int carp_device_event(struct notifier_block *unused,
			     unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct carp_softc *sc;

	switch (event) {
	case NETDEV_UP:
	case NETDEV_CHANGE:
	case NETDEV_DOWN:
		rcu_read_lock();
		list_for_each_entry_rcu(sc, &carp_if_list, sc_global) {
			if (sc->sc_dev == dev) {
				carp_sc_state(sc);
				break;
			}
		}
		rcu_read_unlock();
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block carp_netdev_notifier = {
	.notifier_call = carp_device_event,
};

/*
 * Register/unregister network integration hooks.
 * Called from carp_init/carp_exit.
 */
int carp_netdev_init(void)
{
	int err;

	/* Register protocol 112 handler (CARP) */
	err = inet_add_protocol(&carp_protocol, IPPROTO_CARP);
	if (err) {
		pr_err("Failed to register IPv4 CARP protocol: %d\n", err);
		return err;
	}
#if IS_ENABLED(CONFIG_IPV6)
	err = inet6_add_protocol(&carp6_protocol, IPPROTO_CARP);
	if (err) {
		pr_err("Failed to register IPv6 CARP protocol: %d\n", err);
		inet_del_protocol(&carp_protocol, IPPROTO_CARP);
		return err;
	}
#endif

	/* Register netdev notifier */
	err = register_netdevice_notifier(&carp_netdev_notifier);
	if (err) {
		pr_err("Failed to register netdev notifier: %d\n", err);
#if IS_ENABLED(CONFIG_IPV6)
		inet6_del_protocol(&carp6_protocol, IPPROTO_CARP);
#endif
		inet_del_protocol(&carp_protocol, IPPROTO_CARP);
		return err;
	}

	/* Register NF hooks for source MAC replacement (IPv4 + IPv6) */
	{
		struct nf_hook_ops *ops;
		ops = kzalloc(sizeof(*ops) * 2, GFP_KERNEL);
		if (ops) {
			ops[0].hook = carp_nf_hook;
			ops[0].pf = NFPROTO_IPV4;
			ops[0].hooknum = NF_INET_POST_ROUTING;
			ops[0].priority = NF_IP_PRI_FILTER;
			ops[1].hook = carp_nf_hook;
			ops[1].pf = NFPROTO_IPV6;
			ops[1].hooknum = NF_INET_POST_ROUTING;
			ops[1].priority = NF_IP6_PRI_FILTER;
			if (nf_register_net_hook(&init_net, &ops[0]) == 0 &&
			    nf_register_net_hook(&init_net, &ops[1]) == 0) {
				carp_nf_ops = ops;
			} else {
				nf_unregister_net_hook(&init_net, &ops[0]);
				nf_unregister_net_hook(&init_net, &ops[1]);
				kfree(ops);
				pr_warn("Failed to register netfilter hooks\n");
			}
		}
	}

	return 0;
}

void carp_netdev_exit(void)
{
	/* Unregister NF hooks */
	if (carp_nf_ops) {
		nf_unregister_net_hook(&init_net, &carp_nf_ops[0]);
		nf_unregister_net_hook(&init_net, &carp_nf_ops[1]);
		kfree(carp_nf_ops);
		carp_nf_ops = NULL;
	}

	/* Unregister netdev notifier */
	unregister_netdevice_notifier(&carp_netdev_notifier);

	/* Unregister protocol 112 handler */
#if IS_ENABLED(CONFIG_IPV6)
	inet6_del_protocol(&carp6_protocol, IPPROTO_CARP);
#endif
	inet_del_protocol(&carp_protocol, IPPROTO_CARP);
}
