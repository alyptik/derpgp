/*
 * parse.h:	header for parse.c
 *
 * AUTHORS:	Joey Pabalinas <alyptik@protonmail.com>
 *		Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#ifndef _PARSE_H
#define _PARSE_H 1

#include "defs.h"

/* dispatch table forward declaration */
static size_t (*const dispatch_table[64][2])(PGP_PACKET *restrict);

/* function prototypes */
size_t parse_pubkey_packet(PGP_PACKET *restrict packet);
size_t parse_seckey_packet(PGP_PACKET *restrict packet);
size_t parse_pgp_packets(PGP_LIST *restrict pkts);
size_t read_pgp_aa(FILE *restrict file_ctx, char const *restrict filename, PGP_LIST *restrict list);

static inline size_t free_pubkey_packet(PGP_PACKET *restrict packet)
{
	/* count number of non-NULL pointers */
	size_t ret = !!packet->pubkey.modulus_n.mdata
		+ !!packet->pubkey.exponent.mdata;

	free(packet->pubkey.modulus_n.mdata);
	free(packet->pubkey.exponent.mdata);

	return ret;
}

static inline size_t free_seckey_packet(PGP_PACKET *restrict packet)
{
	/* count number of non-NULL pointers */
	size_t ret = !!packet->seckey.prime_q.mdata
		+ !!packet->seckey.prime_p.mdata
		+ !!packet->seckey.mult_inverse.mdata
		+ !!packet->seckey.exponent_d.mdata;
	free(packet->seckey.exponent_d.mdata);
	free(packet->seckey.mult_inverse.mdata);
	free(packet->seckey.prime_p.mdata);
	free(packet->seckey.prime_q.mdata);
	return ret;
}

static inline void free_pgp_list(PGP_LIST *restrict pkts)
{
	/* return if passed NULL pointers */
	if (!pkts || !pkts->list)
		return;
	for (size_t i = 0; i < pkts->cnt; i++) {
		int packet_type = TAGBITS(pkts->list[i].pheader);
		size_t (*const cleanup_pkt)(PGP_PACKET *restrict) = dispatch_table[packet_type][1];
		if (cleanup_pkt)
			cleanup_pkt(&pkts->list[i]);
		free(pkts->list[i].pdata);
	}
	free(pkts->list);
	pkts->list = NULL;
	pkts->cnt = 0;
	pkts->max = 1;
}

static inline void init_pgp_list(PGP_LIST *restrict pkts)
{
	pkts->cnt = 0;
	pkts->max = 1;
	xcalloc(&pkts->list, 1, sizeof *pkts->list, "error during initial list_ptr calloc()");
}

static inline void add_pgp_list(PGP_LIST *restrict pkts, PGP_PACKET const *restrict packet)
{
	pkts->cnt++;
	/* realloc if cnt reaches current size */
	if (pkts->cnt >= pkts->max) {
		/* check if size too large */
		if (pkts->cnt > ARRAY_MAX)
			ERRX("pkts->cnt > (SIZE_MAX / 2 - 1)");
		pkts->max *= 2;
		xrealloc(&pkts->list, sizeof *pkts->list * pkts->max, "append_packet()");
	}
	pkts->list[pkts->cnt - 1] = *packet;
}

/* read binary pgp format */
static inline size_t read_pgp_bin(FILE *restrict file_ctx, char const *restrict filename, PGP_LIST *restrict list)
{
	FILE *file = file_ctx;
	PGP_PACKET cur = {0};

	/* sanity checks */
	if (!file) {
		free_pgp_list(list);
		init_pgp_list(list);
		/* read the header */
		if (!(file = fopen(filename, "rb")))
			ERR("read_pgp_bin() fopen()");
	}

	/* read header byte */
	if (!xfread(&cur.pheader, 1, sizeof cur.pheader, file))
		goto BASE_CASE;

	/* header type */
	switch (FMTBITS(cur.pheader)) {
	/* old format header */
	case FMT_OLD:
		/* header length */
		switch (cur.pheader & 0x03) {
		/* one byte length */
		case LEN_ONE:
			if (!xfread(&cur.plen_raw, 1, sizeof cur.plen_one, file))
				goto BASE_CASE;
			cur.plen_one = cur.plen_raw[0];
			xcalloc(&cur.pdata, cur.plen_one, sizeof *cur.pdata, "read_pgp() cur.plen_one calloc()");
			if (!xfread(cur.pdata, 1, cur.plen_one, file)) {
				free(cur.pdata);
				goto BASE_CASE;
			}
			break;

		/* two byte length */
		case LEN_TWO:
			if (!xfread(&cur.plen_raw, 1, sizeof cur.plen_two, file))
				goto BASE_CASE;
			cur.plen_two = BETOH16(cur.plen_raw);
			xcalloc(&cur.pdata, cur.plen_two, sizeof *cur.pdata, "read_pgp() cur.plen_two calloc()");
			if (!xfread(cur.pdata, 1, cur.plen_two, file)) {
				free(cur.pdata);
				goto BASE_CASE;
			}
			break;

		/* four byte length */
		case LEN_FOUR:
			if (!xfread(&cur.plen_raw, 1, sizeof cur.plen_four, file))
				goto BASE_CASE;
			cur.plen_four = BETOH32(cur.plen_raw);
			xcalloc(&cur.pdata, cur.plen_four, sizeof *cur.pdata, "read_pgp() cur.plen_four calloc()");
			if (!xfread(cur.pdata, 1, cur.plen_four, file)) {
				free(cur.pdata);
				goto BASE_CASE;
			}
			break;

		/*
		 * indeterminate length
		 *
		 * TODO XXX: add handling for indeterminate packet length
		 */
		case LEN_OTHER: /* fallthrough */
		default:
			goto BASE_CASE;
		}
		break;

	/*
	 * new format header
	 *
	 * TODO XXX: implement new format header handling
	 */
	case FMT_NEW: /* fallthrough */
	/* unrecognized header */
	default:
		goto BASE_CASE;
	}

	/* recurse */
	add_pgp_list(list, &cur);
	return read_pgp_bin(file, filename, list);

/* base-case common exit point */
BASE_CASE:
	fclose(file);
	return list->cnt;
}

/*
 * static function pointer array
 *
 * TODO XXX: implement remaining handlers
 */
static size_t (*const dispatch_table[64][2])(PGP_PACKET *restrict) = {
	[TAG_RSRVD] = {0},
	[TAG_PKESESS] = {0},
	[TAG_SIG] = {0},
	[TAG_SKESESS] = {0},
	[TAG_OPSIG] = {0},
	[TAG_SECKEY] = {parse_seckey_packet, free_seckey_packet},
	[TAG_PUBKEY] = {parse_pubkey_packet, free_pubkey_packet},
	[TAG_SECSUBKEY] = {0},
	[TAG_CDATA] = {0},
	[TAG_SEDATA] = {0},
	[TAG_MARKER] = {0},
	[TAG_LITDATA] = {0},
	[TAG_TRUST] = {0},
	[TAG_UID] = {0},
	[TAG_PUBSUBKEY] = {0},
	[TAG_UATTR] = {0},
	[TAG_SEIPDATA] = {0},
	[TAG_MDCODE] = {0},
	[TAG_PRVT0] = {0},
	[TAG_PRVT1] = {0},
	[TAG_PRVT2] = {0},
	[TAG_PRVT3] = {0},
};

#endif
