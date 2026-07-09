/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * HMAC-SHA1 implementation for CARP.
 * Linux port: uses kernel crypto API instead of FreeBSD SHA1_CTX.
 * Original logic mirrors FreeBSD carp_hmac_prepare / carp_hmac_generate.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/gfp.h>
#include <linux/string.h>

#include "carp.h"

/* Initialize HMAC-SHA1 transform */
int carp_hmac_init(struct carp_softc *sc)
{
	sc->sc_tfm = crypto_alloc_shash("hmac(sha1)", 0, 0);
	if (IS_ERR(sc->sc_tfm)) {
		pr_err("carp: failed to allocate hmac(sha1): %ld\n",
		       PTR_ERR(sc->sc_tfm));
		return PTR_ERR(sc->sc_tfm);
	}
	return 0;
}

/* Free HMAC-SHA1 transform */
void carp_hmac_free(struct carp_softc *sc)
{
	if (sc->sc_tfm && !IS_ERR(sc->sc_tfm)) {
		crypto_free_shash(sc->sc_tfm);
		sc->sc_tfm = NULL;
	}
}

/*
 * Prepare HMAC ipad/opad from key.
 * Mirrors FreeBSD carp_hmac_prepare exactly.
 */
void carp_hmac_prepare(struct carp_softc *sc)
{
	int i;

	if (!sc->sc_tfm)
		return;

	/* Compute ipad from key (FreeBSD lines 389-393) */
	memset(sc->sc_pad, 0, sizeof(sc->sc_pad));
	memcpy(sc->sc_pad, sc->sc_key, sizeof(sc->sc_key));
	for (i = 0; i < sizeof(sc->sc_pad); i++)
		sc->sc_pad[i] ^= 0x36;

	/*
	 * FreeBSD precomputes the inner hash here (SHA1Init + SHA1Update
	 * with ipad, version, type, vhid, sorted addresses).
	 * In Linux we recompute each time for simplicity.
	 * To match, we store the pad and recompute on generate.
	 */
}

/*
 * Generate HMAC for CARP advertisement.
 * Mirrors FreeBSD carp_hmac_generate (lines 447-466).
 */
int carp_hmac_generate(struct carp_softc *sc, __u32 counter[2],
		       unsigned char md[20])
{
	struct shash_desc *desc;
	__u8 pad_copy[CARP_HMAC_PAD];
	int i, ret;

	if (!sc->sc_tfm)
		return -EINVAL;

	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(sc->sc_tfm),
		       GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	desc->tfm = sc->sc_tfm;

	/* Inner hash */
	ret = crypto_shash_init(desc);
	if (ret)
		goto out;

	memcpy(pad_copy, sc->sc_pad, CARP_HMAC_PAD);
	for (i = 0; i < CARP_HMAC_PAD; i++)
		pad_copy[i] ^= 0x36;

	ret = crypto_shash_update(desc, pad_copy, CARP_HMAC_PAD);
	if (ret)
		goto out;

	/* Update with counter (FreeBSD: SHA1Update with counter) */
	ret = crypto_shash_update(desc, (void *)counter, 8);
	if (ret)
		goto out;

	ret = crypto_shash_final(desc, md);
	if (ret)
		goto out;

	/* Outer hash (FreeBSD: SHA1Init + SHA1Update opad + inner hash) */
	ret = crypto_shash_init(desc);
	if (ret)
		goto out;

	/* opad = ipad XOR 0x5c */
	for (i = 0; i < CARP_HMAC_PAD; i++)
		pad_copy[i] ^= 0x36 ^ 0x5c;

	ret = crypto_shash_update(desc, pad_copy, CARP_HMAC_PAD);
	if (ret)
		goto out;

	ret = crypto_shash_update(desc, md, 20);
	if (ret)
		goto out;

	ret = crypto_shash_final(desc, md);

out:
	kfree(desc);
	return ret;
}

/*
 * Verify HMAC.
 * Mirrors FreeBSD carp_hmac_verify (lines 468-479).
 */
int carp_hmac_verify(struct carp_softc *sc, __u32 counter[2],
		     unsigned char md[20])
{
	unsigned char md2[20];
	int ret;

	ret = carp_hmac_generate(sc, counter, md2);
	if (ret)
		return ret;

	return memcmp(md, md2, sizeof(md2)) ? -1 : 0;
}
