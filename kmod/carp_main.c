/* SPDX-License-Identifier: BSD-2-Clause */
#include "carp_internal.h"
#include <linux/netdevice.h>
#include <linux/igmp.h>
#include <net/if_inet6.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

/*

/* Module parameters */
int carp_allow = 1;
module_param(carp_allow, int, 0644);
MODULE_PARM_DESC(carp_allow, "Accept incoming CARP packets (1=yes, 0=no)");

int carp_preempt;
module_param(carp_preempt, int, 0644);
MODULE_PARM_DESC(carp_preempt, "Preempt slower masters");

int carp_log = 1;
module_param(carp_log, int, 0644);
MODULE_PARM_DESC(carp_log, "Log level (0=off, 1=info, 2=debug)");

int carp_dscp = 56;
module_param(carp_dscp, int, 0644);
MODULE_PARM_DESC(carp_dscp, "DSCP value for CARP packets (0-63)");

int carp_demotion_param;
module_param(carp_demotion_param, int, 0644);
MODULE_PARM_DESC(carp_demotion_param, "Global demotion factor (skew of advskew)");

int carp_senderr_adj = CARP_MAXSKEW;
module_param(carp_senderr_adj, int, 0644);
MODULE_PARM_DESC(carp_senderr_adj, "Send error demotion factor (default 240)");

int carp_ifdown_adj = CARP_MAXSKEW;
module_param(carp_ifdown_adj, int, 0644);
MODULE_PARM_DESC(carp_ifdown_adj, "Interface down demotion factor (default 240)");

/* Global state */
DEFINE_RWLOCK(carp_lock);
LIST_HEAD(carp_if_list);
int carp_demotion;
struct nf_hook_ops *carp_nf_ops;
struct work_struct carp_sendall_work;
#define CARP_SENDAD_MAX_ERRORS  3
#define CARP_SENDAD_MIN_SUCCESS 3
#define CARP_MAXSKEW 240

/* Global statistics */
struct carpstats __percpu *carp_stats;

#define CARPSTATS_INC(name)	\
	this_cpu_inc(carp_stats->name)
int carp_is_supported_dev(struct net_device *dev)
{
	if (!dev)
		return -ENXIO;

	switch (dev->type) {
	case ARPHRD_ETHER:
	case ARPHRD_EETHER:
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

/* Lookup a carp_softc by VHID on a given device */
struct carp_softc *sc_lookup_vhid(struct net_device *dev, int vhid)
{
	struct carp_if *cif;
	struct carp_softc *sc;

	rcu_read_lock();
	list_for_each_entry_rcu(cif, &carp_if_list, cif_list) {
		if (cif->cif_dev != dev)
			continue;
		list_for_each_entry(sc, &cif->cif_list, sc_list) {
			if (sc->sc_vhid == vhid) {
				rcu_read_unlock();
				return sc;
			}
		}
	}
	rcu_read_unlock();
	return NULL;
}


/*
 * Set CARP state and log the transition.
 */
void carp_set_state(struct carp_softc *sc, int state, const char *reason)
{
	static const char *states[] = { CARP_STATES };

	if (sc->sc_state != state) {
		pr_info("VHID %u@%s: %s -> %s (%s)\n",
			sc->sc_vhid, sc->sc_dev->name,
			states[sc->sc_state], states[state], reason);
		sc->sc_state = state;

		/* Send uevent for monitoring */
		{
			char *envp[4];
			char env_buf[3][64];
			snprintf(env_buf[0], 64, "CARP_STATE=%s", states[state]);
			snprintf(env_buf[1], 64, "VHID=%d", sc->sc_vhid);
			snprintf(env_buf[2], 64, "IFNAME=%s", sc->sc_dev->name);
			envp[0] = env_buf[0];
			envp[1] = env_buf[1];
			envp[2] = env_buf[2];
			envp[3] = NULL;
			kobject_uevent_env(&sc->sc_dev->dev.kobj,
					   KOBJ_CHANGE, envp);
		}
	}
}

/*
 * Send gratuitous ARP when becoming MASTER.
 */


/*
 * Handle interface state changes.
 */
void carp_sc_state(struct carp_softc *sc)
{
	if (!netif_running(sc->sc_dev) ||
	    !netif_carrier_ok(sc->sc_dev) ||
	    !carp_allow) {
		del_timer_sync(&sc->sc_ad_timer);
		del_timer_sync(&sc->sc_md_timer);
		del_timer_sync(&sc->sc_md6_timer);
		carp_set_state(sc, CARP_STATE_INIT, "hardware interface down");
		carp_setrun(sc, 0);
		carp_delroute(sc);
		if (!sc->sc_suppress) {
			carp_demote_adj(carp_ifdown_adj, "interface down");
			sc->sc_suppress = 1;
		}
	} else {
		carp_set_state(sc, CARP_STATE_INIT, "hardware interface up");
		carp_setrun(sc, 0);
		if (sc->sc_suppress)
			carp_demote_adj(-carp_ifdown_adj, "interface up");
		sc->sc_suppress = 0;
	}
}

/* Netdev event handler */
static int carp_device_event(struct notifier_block *unused,
			     unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct carp_softc *sc;

	switch (event) {
	case NETDEV_UP:
	case NETDEV_CARRIER_ON:
	case NETDEV_DOWN:
	case NETDEV_CARRIER_OFF:
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
 * Allocate a new CARP interface.
 */
struct carp_if *carp_alloc_if(struct net_device *dev)
{
	struct carp_if *cif;

	cif = kzalloc(sizeof(*cif), GFP_KERNEL);
	if (!cif)
		return NULL;

	spin_lock_init(&cif->cif_lock);
	cif->cif_dev = dev;
	INIT_LIST_HEAD(&cif->cif_list);

	/* Enable promiscuous mode to receive CARP packets for virtual MAC */
	if (dev_set_promiscuity(dev, 1) == 0)
		cif->cif_flags |= CIF_PROMISC;
	else
		pr_warn("%s: failed to set promiscuous on %s\n",
			__func__, dev->name);

	write_lock(&carp_lock);
	list_add_tail_rcu(&cif->cif_list, &carp_if_list);
	write_unlock(&carp_lock);

	return cif;
}

void carp_free_if(struct carp_if *cif)
{
	/* Disable promiscuous mode */
	if (cif->cif_flags & CIF_PROMISC)
		dev_set_promiscuity(cif->cif_dev, -1);

	write_lock(&carp_lock);
	list_del_rcu(&cif->cif_list);
	write_unlock(&carp_lock);
	synchronize_rcu();
	kfree(cif);
}

/*
 * Allocate a new CARP softc for a VHID.
 */
struct carp_softc *carp_alloc(struct net_device *dev, int vhid)
{
	struct carp_softc *sc;
	struct carp_if *cif;

	/* Find or create carp_if */
	rcu_read_lock();
	list_for_each_entry_rcu(cif, &carp_if_list, cif_list) {
		if (cif->cif_dev == dev) {
			rcu_read_unlock();
			goto found;
		}
	}
	rcu_read_unlock();

	cif = carp_alloc_if(dev);
	if (!cif)
		return NULL;

found:
	sc = kzalloc(sizeof(*sc), GFP_KERNEL);
	if (!sc)
		return NULL;

	sc->sc_advbase = CARP_DFLTINTV;
	sc->sc_vhid = vhid;
	sc->sc_init_counter = 1;
	sc->sc_state = CARP_STATE_INIT;
	sc->sc_dev = dev;
	sc->sc_cif = cif;

	/* Set virtual MAC: 00:00:5e:00:01:XX where XX = vhid */
	sc->sc_lladdr[0] = 0x00;
	sc->sc_lladdr[1] = 0x00;
	sc->sc_lladdr[2] = 0x5e;
	sc->sc_lladdr[3] = 0x00;
	sc->sc_lladdr[4] = 0x01;
	sc->sc_lladdr[5] = vhid & 0xff;

	/* Default CARP multicast addresses */
	sc->sc_carpaddr.s_addr = htonl(0xe0000012);	/* 224.0.0.18 */
	memset(&sc->sc_carpaddr6, 0, sizeof(sc->sc_carpaddr6));
	sc->sc_carpaddr6.s6_addr[0] = 0xff;
	sc->sc_carpaddr6.s6_addr[1] = 0x02;
	sc->sc_carpaddr6.s6_addr[15] = 0x12;

	/* Initialize timers */
	timer_setup(&sc->sc_ad_timer, carp_send_ad_timer, 0);
	timer_setup(&sc->sc_md_timer, carp_master_down_timer, 0);
	timer_setup(&sc->sc_md6_timer, carp_master_down6_timer, 0);

	/* Allocate address arrays */
	sc->sc_ifas4_max = 4;
	sc->sc_ifas4 = kcalloc(sc->sc_ifas4_max, sizeof(*sc->sc_ifas4),
			       GFP_KERNEL);
	sc->sc_ifas6_max = 4;
	sc->sc_ifas6 = kcalloc(sc->sc_ifas6_max, sizeof(*sc->sc_ifas6),
			       GFP_KERNEL);

	if (!sc->sc_ifas4 || !sc->sc_ifas6) {
		kfree(sc->sc_ifas4);
		kfree(sc->sc_ifas6);
		kfree(sc);
		return NULL;
	}

	spin_lock(&cif->cif_lock);
	list_add_tail(&sc->sc_list, &cif->cif_list);
	spin_unlock(&cif->cif_lock);

	write_lock(&carp_lock);
	list_add_tail_rcu(&sc->sc_global, &carp_if_list);
	write_unlock(&carp_lock);

	return sc;
}

void carp_destroy(struct carp_softc *sc)
{
	del_timer_sync(&sc->sc_ad_timer);
	del_timer_sync(&sc->sc_md_timer);
	del_timer_sync(&sc->sc_md6_timer);
	cancel_work_sync(&sc->sc_work);
	flush_work(&carp_sendall_work);

	spin_lock(&sc->sc_cif->cif_lock);
	list_del(&sc->sc_list);
	spin_unlock(&sc->sc_cif->cif_lock);

	write_lock(&carp_lock);
	list_del_rcu(&sc->sc_global);
	write_unlock(&carp_lock);
	synchronize_rcu();

	kfree(sc->sc_ifas4);
	kfree(sc->sc_ifas6);
	kfree(sc);
}

/* Grow the IPv4 address array */
int carp_grow_ifas4(struct carp_softc *sc)
{
	struct in_ifaddr **new;
	int new_max = sc->sc_ifas4_max * 2;

	new = kcalloc(new_max, sizeof(*new), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	memcpy(new, sc->sc_ifas4, sc->sc_ifas4_max * sizeof(*new));
	kfree(sc->sc_ifas4);
	sc->sc_ifas4 = new;
	sc->sc_ifas4_max = new_max;
	return 0;
}

/* Grow the IPv6 address array */
int carp_grow_ifas6(struct carp_softc *sc)
{
	struct in6_ifaddr **new;
	int new_max = sc->sc_ifas6_max * 2;

	new = kcalloc(new_max, sizeof(*new), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	memcpy(new, sc->sc_ifas6, sc->sc_ifas6_max * sizeof(*new));
	kfree(sc->sc_ifas6);
	sc->sc_ifas6 = new;
	sc->sc_ifas6_max = new_max;
	return 0;
}

/*
 * Attach an address to a CARP VHID.
 */
int carp_attach_address(struct carp_softc *sc, int af, void *addr)
{
	int ret = 0;

	switch (af) {
	case AF_INET: {
		struct in_ifaddr *ifa = addr;

		spin_lock(&sc->sc_cif->cif_lock);
		if (sc->sc_naddrs >= sc->sc_ifas4_max) {
			ret = carp_grow_ifas4(sc);
			if (ret) {
				spin_unlock(&sc->sc_cif->cif_lock);
				return ret;
			}
		}
		in_dev_hold(ifa->ifa_dev);
		sc->sc_ifas4[sc->sc_naddrs++] = ifa;
		sc->sc_cif->cif_naddrs++;
		spin_unlock(&sc->sc_cif->cif_lock);

		carp_hmac_prepare(sc);
		carp_sc_state(sc);
		break;
	}
	case AF_INET6: {
		struct in6_ifaddr *ifa6 = addr;

		spin_lock(&sc->sc_cif->cif_lock);
		if (sc->sc_naddrs6 >= sc->sc_ifas6_max) {
			ret = carp_grow_ifas6(sc);
			if (ret) {
				spin_unlock(&sc->sc_cif->cif_lock);
				return ret;
			}
		}
		in6_dev_hold(ifa6->idev);
		sc->sc_ifas6[sc->sc_naddrs6++] = ifa6;
		sc->sc_cif->cif_naddrs6++;
		spin_unlock(&sc->sc_cif->cif_lock);

		carp_hmac_prepare(sc);
		carp_sc_state(sc);
		break;
	}
	default:
		return -EPROTONOSUPPORT;
	}

	return 0;
}

/*
 * Detach an address from a CARP VHID.
 */
void carp_detach_address(struct carp_softc *sc, int af, void *addr)
{
	int i;

	switch (af) {
	case AF_INET: {
		struct in_ifaddr *ifa = addr;

		spin_lock(&sc->sc_cif->cif_lock);
		for (i = 0; i < sc->sc_naddrs; i++) {
			if (sc->sc_ifas4[i] == ifa) {
				sc->sc_naddrs--;
				sc->sc_cif->cif_naddrs--;
				if (i < sc->sc_naddrs)
					memmove(&sc->sc_ifas4[i],
						&sc->sc_ifas4[i + 1],
						(sc->sc_naddrs - i) * sizeof(*sc->sc_ifas4));
				sc->sc_ifas4[sc->sc_naddrs] = NULL;
				in_dev_put(ifa->ifa_dev);
				break;
			}
		}
		spin_unlock(&sc->sc_cif->cif_lock);
		break;
	}
	case AF_INET6: {
		struct in6_ifaddr *ifa6 = addr;

		spin_lock(&sc->sc_cif->cif_lock);
		for (i = 0; i < sc->sc_naddrs6; i++) {
			if (sc->sc_ifas6[i] == ifa6) {
				sc->sc_naddrs6--;
				sc->sc_cif->cif_naddrs6--;
				if (i < sc->sc_naddrs6)
					memmove(&sc->sc_ifas6[i],
						&sc->sc_ifas6[i + 1],
						(sc->sc_naddrs6 - i) * sizeof(*sc->sc_ifas6));
				sc->sc_ifas6[sc->sc_naddrs6] = NULL;
				in6_dev_put(ifa6->idev);
				break;
			}
		}
		spin_unlock(&sc->sc_cif->cif_lock);
		break;
	}
	}

	carp_hmac_prepare(sc);
	carp_sc_state(sc);
	carp_multicast_setup(sc);

	if (sc->sc_naddrs == 0 && sc->sc_naddrs6 == 0)
		carp_destroy(sc);
}

/*
 * /proc/net/carp_stats


/*
 * /proc/net/carp_stats
 */
static int carp_stats_show(struct seq_file *m, void *v)
{
	int cpu;
	struct carpstats sum = {};

	for_each_possible_cpu(cpu) {
		struct carpstats *s = per_cpu_ptr(carp_stats, cpu);
		sum.carps_ipackets += s->carps_ipackets;
		sum.carps_ipackets6 += s->carps_ipackets6;
		sum.carps_badif += s->carps_badif;
		sum.carps_badttl += s->carps_badttl;
		sum.carps_hdrops += s->carps_hdrops;
		sum.carps_badsum += s->carps_badsum;
		sum.carps_badver += s->carps_badver;
		sum.carps_badlen += s->carps_badlen;
		sum.carps_badauth += s->carps_badauth;
		sum.carps_badvhid += s->carps_badvhid;
		sum.carps_badaddrs += s->carps_badaddrs;
		sum.carps_opackets += s->carps_opackets;
		sum.carps_opackets6 += s->carps_opackets6;
		sum.carps_onomem += s->carps_onomem;
		sum.carps_ostates += s->carps_ostates;
		sum.carps_preempt += s->carps_preempt;
	}

	seq_printf(m,
		"CARP statistics:\n"
		"  IPv4 input packets:  %llu\n"
		"  IPv6 input packets:  %llu\n"
		"  Bad interface:       %llu\n"
		"  Bad TTL:             %llu\n"
		"  Header drops:        %llu\n"
		"  Bad checksum:        %llu\n"
		"  Bad version:         %llu\n"
		"  Bad length:          %llu\n"
		"  Bad auth:            %llu\n"
		"  Bad VHID:            %llu\n"
		"  Bad addresses:       %llu\n"
		"  IPv4 output packets: %llu\n"
		"  IPv6 output packets: %llu\n"
		"  No memory:           %llu\n"
		"  State updates:       %llu\n"
		"  Preemptions:         %llu\n",
		sum.carps_ipackets, sum.carps_ipackets6,
		sum.carps_badif, sum.carps_badttl,
		sum.carps_hdrops, sum.carps_badsum,
		sum.carps_badver, sum.carps_badlen,
		sum.carps_badauth, sum.carps_badvhid,
		sum.carps_badaddrs,
		sum.carps_opackets, sum.carps_opackets6,
		sum.carps_onomem, sum.carps_ostates,
		sum.carps_preempt);

	return 0;
}
static int carp_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, carp_stats_show, NULL);
}

static const struct proc_ops carp_stats_pops = {
	.proc_open = carp_stats_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};


static struct proc_dir_entry *carp_proc_entry;

/*
 * /proc/net/carp_interfaces - show CARP interface state
 */
static int carp_ifaces_show(struct seq_file *m, void *v)
{
	struct carp_softc *sc;
	static const char *states[] = { CARP_STATES };

	rcu_read_lock();
	list_for_each_entry_rcu(sc, &carp_if_list, sc_global) {
		seq_printf(m, "%s\tvhid %d\tstate %s\tadvbase %d\tadvskew %d\n",
			   sc->sc_dev->name, sc->sc_vhid,
			   states[sc->sc_state],
			   sc->sc_advbase, sc->sc_advskew);
	}
	rcu_read_unlock();

	return 0;
}
static int carp_ifaces_open(struct inode *inode, struct file *file)
{
	return single_open(file, carp_ifaces_show, NULL);
}

static const struct proc_ops carp_ifaces_pops = {
	.proc_open = carp_ifaces_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

/*
 * Netlink Generic Family
 */
static struct genl_family carp_genl_family;


/*
 * Module init/exit
 */
/*
 * Netfilter hook: replace source MAC for CARP traffic.
 * FreeBSD: carp_output() — checks all outgoing traffic on CARP interface
 * Linux: NF_INET(6)_POST_ROUTING hook for both IPv4 and IPv6
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

static int __init carp_init(void)
{
	int ret;

	/* Allocate per-CPU stats */
	carp_stats = alloc_percpu(struct carpstats);
	if (!carp_stats)
		return -ENOMEM;

	/* Initialize HMAC */
	ret = carp_hmac_init();
	if (ret) {
		pr_err("Failed to initialize HMAC: %d\n", ret);
		goto err_stats;
	}

	/* Initialize sendall work */
	INIT_WORK(&carp_sendall_work, carp_sendall_work_func);

	/* Register netlink family */
	ret = genl_register_family(&carp_genl_family);
	if (ret) {
		pr_err("Failed to register netlink family: %d\n", ret);
		goto err_hmac;
	}

	/* Register netdev notifier */
	ret = register_netdevice_notifier(&carp_netdev_notifier);
	if (ret) {
		pr_err("Failed to register netdev notifier: %d\n", ret);
		goto err_genl;
	}

	/* Create /proc entries */
	carp_proc_entry = proc_mkdir("net/carp", NULL);
	if (!carp_proc_entry) {
		pr_warn("Failed to create /proc/net/carp\n");
		/* Non-fatal, continue */
	} else {
		proc_create("stats", 0444, carp_proc_entry, &carp_stats_pops);
		proc_create("interfaces", 0444, carp_proc_entry, &carp_ifaces_pops);
	}

	/* Register netfilter hooks for source MAC replacement (IPv4 + IPv6) */
	{
		struct nf_hook_ops *ops;
		ops = kzalloc(sizeof(*ops) * 2, GFP_KERNEL);
		if (ops) {
			/* IPv4 hook */
			ops[0].hook = carp_nf_hook;
			ops[0].pf = NFPROTO_IPV4;
			ops[0].hooknum = NF_INET_POST_ROUTING;
			ops[0].priority = NF_IP_PRI_FILTER;
			/* IPv6 hook */
			ops[1].hook = carp_nf_hook;
			ops[1].pf = NFPROTO_IPV6;
			ops[1].hooknum = NF_INET6_POST_ROUTING;
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

	pr_info("CARP module loaded (allow=%d, preempt=%d)\n",
		carp_allow, carp_preempt);
	return 0;

err_genl:
	genl_unregister_family(&carp_genl_family);
err_hmac:
	carp_hmac_fini();
err_stats:
	free_percpu(carp_stats);
	return ret;
}

static void __exit carp_exit(void)
{
	struct carp_softc *sc, *tmp;

	/* Destroy all CARP instances */
	write_lock(&carp_lock);
	list_for_each_entry_safe(sc, tmp, &carp_if_list, sc_global) {
		del_timer_sync(&sc->sc_ad_timer);
		del_timer_sync(&sc->sc_md_timer);
		del_timer_sync(&sc->sc_md6_timer);
		cancel_work_sync(&sc->sc_work);
	flush_work(&carp_sendall_work);
		list_del_rcu(&sc->sc_global);
		kfree(sc->sc_ifas4);
		kfree(sc->sc_ifas6);
		kfree(sc);
	}
	write_unlock(&carp_lock);
	synchronize_rcu();

	unregister_netdevice_notifier(&carp_netdev_notifier);
	genl_unregister_family(&carp_genl_family);
	carp_hmac_fini();

	/* Unregister netfilter hook */
	if (carp_nf_ops) {
		nf_unregister_net_hook(&init_net, &carp_nf_ops[0]);
		nf_unregister_net_hook(&init_net, &carp_nf_ops[1]);
		kfree(carp_nf_ops);
		carp_nf_ops = NULL;
	}

	if (carp_proc_entry) {
		remove_proc_entry("interfaces", carp_proc_entry);
		remove_proc_entry("stats", carp_proc_entry);
		remove_proc_entry("net/carp", NULL);
	}

	free_percpu(carp_stats);
	pr_info("CARP module unloaded\n");
}

module_init(carp_init);
module_exit(carp_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Ported from FreeBSD CARP");
MODULE_DESCRIPTION("Common Address Redundancy Protocol (CARP) for Linux");
MODULE_VERSION("1.0.0");

