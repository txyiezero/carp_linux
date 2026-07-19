/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * CARP internal header — shared declarations for all source files.
 */
#ifndef _CARP_INTERNAL_H
#define _CARP_INTERNAL_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/rwlock.h>
#include <linux/workqueue.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/hashtable.h>
#include <net/ip.h>
#include <net/ip6_checksum.h>
#include <net/ndisc.h>
#include <net/ipv6.h>
#include <net/addrconf.h>
#include <net/ip6_route.h>
#include <net/route.h>
#include <net/arp.h>
#include <net/genetlink.h>
#include <crypto/hash.h>

#include "../include/carp.h"

/* ---- Module parameters (carp_main.c) ---- */
extern int carp_allow;
extern int carp_preempt;
extern int carp_log;
extern int carp_dscp;
extern int carp_senderr_adj;
extern int carp_ifdown_adj;

/* ---- Global state (carp_main.c) ---- */
extern rwlock_t carp_lock;
extern struct list_head carp_if_list;
extern int carp_demotion;
extern struct carpstats __percpu *carp_stats;

#define CARPSTATS_INC(name)  this_cpu_inc(carp_stats->name)
#define CARPSTATS_ADD(name, val) this_cpu_add(carp_stats->name, (val))

#define CARP_SENDAD_MAX_ERRORS  3
#define CARP_SENDAD_MIN_SUCCESS 3

#define DEMOTE_ADVSKEW(sc) \
	(((sc)->sc_advskew + carp_demotion > CARP_MAXSKEW) ? \
	 CARP_MAXSKEW : \
	 (((sc)->sc_advskew + carp_demotion < 0) ? \
	  0 : ((sc)->sc_advskew + carp_demotion)))

/* ---- Data structures ---- */
struct carp_if {
	struct list_head cif_list;
	int cif_naddrs;
	int cif_naddrs6;
	struct net_device *cif_dev;
	spinlock_t cif_lock;
	u32 cif_flags;
#define CIF_PROMISC 0x00000001
};

struct carp_softc {
	struct list_head sc_list;
	struct list_head sc_global;
	int sc_vhid;
	int sc_advskew;
	int sc_advbase;
	int sc_state;
	int sc_suppress;
	int sc_sendad_errors;
	int sc_sendad_success;
	int sc_init_counter;
	u64 sc_counter;

	struct in_addr sc_carpaddr;
	struct in6_addr sc_carpaddr6;
	int sc_naddrs;
	int sc_naddrs6;

	struct in_ifaddr **sc_ifas4;
	struct inet6_ifaddr **sc_ifas6;
	int sc_ifas4_max;
	int sc_ifas6_max;

	struct net_device *sc_dev;
	struct carp_if *sc_cif;

	u8 sc_lladdr[ETH_ALEN];

	u8 sc_key[CARP_KEY_LEN];

	struct timer_list sc_ad_timer;
	struct timer_list sc_md_timer;
	struct timer_list sc_md6_timer;
	struct work_struct sc_work;

	struct rcu_head rcu;
};

/* ---- Function declarations: carp_input.c ---- */
int carp_hmac_init(void);
void carp_hmac_fini(void);
void carp_hmac_generate(struct carp_softc *sc, u32 counter[2], u8 md[20]);
int carp_hmac_verify(struct carp_softc *sc, u32 counter[2], u8 md[20]);
void carp_input_c(struct sk_buff *skb, struct carp_header *ch, int af, int ttl);
int carp_input4(struct sk_buff *skb);
int carp_input6(struct sk_buff *skb);

/* ---- Function declarations: carp_output.c ---- */
void carp_prepare_ad(struct carp_softc *sc, struct carp_header *ch, u32 counter[2]);
void carp_send_ad_locked(struct carp_softc *sc);
void carp_send_ad_timer(struct timer_list *t);
void carp_send_ad_error(struct carp_softc *sc, int error);
void carp_send_arp(struct carp_softc *sc);
void carp_setrun(struct carp_softc *sc, int af);
void carp_master_down_locked(struct carp_softc *sc, const char *reason);
void carp_master_down_timer(struct timer_list *t);
void carp_master_down6_timer(struct timer_list *t);
void carp_set_state(struct carp_softc *sc, int state, const char *reason);

/* ---- Function declarations: carp_main.c ---- */
struct carp_softc *sc_lookup_vhid(struct net_device *dev, int vhid);
void carp_sc_state(struct carp_softc *sc);
void carp_demote_adj(int adj, const char *reason);
void carp_sendall_work_func(struct work_struct *work);
struct carp_if *carp_alloc_if(struct net_device *dev);
void carp_free_if(struct carp_if *cif);
struct carp_softc *carp_alloc(struct net_device *dev, int vhid);
void carp_destroy(struct carp_softc *sc);
int carp_grow_ifas4(struct carp_softc *sc);
int carp_grow_ifas6(struct carp_softc *sc);
int carp_attach_address(struct carp_softc *sc, int af, void *addr);
void carp_detach_address(struct carp_softc *sc, int af, void *addr);

/* ---- Function declarations: carp_netlink.c ---- */
void carp_multicast_setup(struct carp_softc *sc);
void carp_multicast_cleanup(struct carp_softc *sc);
int carp_iamatch4(struct net_device *dev, __be32 addr);
struct inet6_ifaddr *carp_iamatch6(struct net_device *dev, const struct in6_addr *addr);
u8 *carp_macmatch6(struct net_device *dev, const struct in6_addr *addr);
int carp_forus(struct net_device *dev, const u8 *dhost);
int carp_is_master(struct net_device *dev, int vhid);
int carp_get_vhid(struct net_device *dev, __be32 addr);
extern struct work_struct carp_sendall_work;
extern struct list_head carp_if_list;
extern rwlock_t carp_lock;
extern struct carpstats __percpu *carp_stats;

/* ---- Source address selection (carp_output.c) ---- */
struct in_ifaddr *carp_best_ifa4(struct net_device *dev);
struct inet6_ifaddr *carp_best_ifa6(struct net_device *dev);

/* ---- Network device integration (carp_netdev.c) ---- */
int carp_netdev_init(void);
void carp_netdev_exit(void);

#endif /* _CARP_INTERNAL_H */
