/* SPDX-License-Identifier: BSD-2-Clause */
#include "carp_internal.h"

/*
 * Add routes when becoming MASTER.
 */
void carp_addroute(struct carp_softc *sc)
{
	int i;

	/* IPv4 routes */
	for (i = 0; i < sc->sc_naddrs; i++) {
		if (!sc->sc_ifas4[i])
			continue;
		{
			struct fib_config cfg = {
				.fc_table = RT_TABLE_LOCAL,
				.fc_scope = RT_SCOPE_HOST,
				.fc_type = RTN_LOCAL,
				.fc_dst = sc->sc_ifas4[i]->ifa_local,
				.fc_dst_len = 32,
				.fc_oif = sc->sc_dev,
			};
			ip_fib_configure(0, &cfg);
		}
	}

	/* IPv6 routes */
	for (i = 0; i < sc->sc_naddrs6; i++) {
		if (!sc->sc_ifas6[i])
			continue;
		{
			struct fib6_config cfg6 = {
				.fc_table = RT_TABLE_LOCAL,
				.fc_scope = RT_SCOPE_HOST,
				.fc_type = RTN_LOCAL,
				.fc_dst = sc->sc_ifas6[i]->addr,
				.fc_dst_len = 128,
			};
			ip6_route_add(&cfg6);
		}
	}
}

/*
 * Delete routes when becoming BACKUP/INIT.
 */
void carp_delroute(struct carp_softc *sc)
{
	int i;

	/* IPv4 routes */
	for (i = 0; i < sc->sc_naddrs; i++) {
		if (!sc->sc_ifas4[i])
			continue;
		{
			struct fib_config cfg = {
				.fc_table = RT_TABLE_LOCAL,
				.fc_scope = RT_SCOPE_HOST,
				.fc_type = RTN_LOCAL,
				.fc_dst = sc->sc_ifas4[i]->ifa_local,
				.fc_dst_len = 32,
				.fc_oif = sc->sc_dev,
			};
			ip_fib_configure(0, &cfg);
		}
	}

	/* IPv6 routes */
	for (i = 0; i < sc->sc_naddrs6; i++) {
		if (!sc->sc_ifas6[i])
			continue;
		{
			struct fib6_config cfg6 = {
				.fc_table = RT_TABLE_LOCAL,
				.fc_scope = RT_SCOPE_HOST,
				.fc_type = RTN_LOCAL,
				.fc_dst = sc->sc_ifas6[i]->addr,
				.fc_dst_len = 128,
			};
			ip6_route_del(&cfg6);
		}
	}
}

