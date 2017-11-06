/*
 * parse.c:	option parsing
 *
 * AUTHORS:	Joey Pabalinas <alyptik@protonmail.com>
 *		Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#include "parse.h"

/* extern inline prototypes to prevent linker errors */
extern inline void free_pgp_pubkey(pgp_packet *restrict packet);
extern inline void free_pgp_seckey(pgp_packet *restrict packet);
extern inline void free_pgp_list(pgp_list *restrict list_struct);
extern inline void init_pgp_list(pgp_list *restrict list_struct);
extern inline void add_pgp_list(pgp_list *restrict list_struct, pgp_packet const *restrict packet);
extern inline size_t read_pgp_bin(FILE *file_ctx, char const *restrict filename, pgp_list *restrict list);

/*
 * static function pointer array
 *
 * TODO XXX: implement handlers
 */
static size_t (*const dispatch_table[])(pgp_packet *restrict) = {
	/* &parse_rsrvd_packet, &parse_pkesess_packet, &parse_skesess_packet, */
	0, 0, 0,
	/* &parse_opsig_packet, &parse_seckey_packet, &parse_pubkey_packet, */
	0, &parse_seckey_packet, &parse_pubkey_packet,
	/* &parse_cdata_packet, &parse_secsubkey_packet, &parse_sedat_packet, */
	0, 0, 0,
	/* &parse_marker_packet, &parse_litdata_packet, &parse_trust_packet, */
	0, 0, 0,
	/* &parse_ui_packet, &parse_pubsubkey_packet, */
	0, 0, 0,
	/* &two &placeholder &indices */
	0, 0,
	/* &parse_uattr_packet, &parse_seipdata_packet, &parse_mdcode_packet, */
	0, 0, 0,
	/* &ten &placeholder &indices */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* &ten &placeholder &indices */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* &parse_prvt0, &parse_prvt1_packet, &parse_prvt2_packet, &parse_prvt3_packet, */
	0, 0, 0, 0,
};

/* dispatch each packet to a parser */
size_t parse_pgp_packets(pgp_list *restrict pkts)
{
	size_t i = 0;
	if (!pkts)
		ERRX("NULL list passed to parse_pgp_packets()");
	for (i = 0; i < pkts->cnt; i++) {
		int packet_type = (pkts->list[i].pheader & 0x3c) >> 2;
		size_t (*const parse)(pgp_packet *restrict) = dispatch_table[packet_type];
		if (parse)
			parse(&pkts->list[i]);
	}
	return i;
}

/* read ascii armor pgp format */
size_t read_pgp_aa(FILE *file_ctx, char const *restrict filename, pgp_list *restrict list)
{
	/* silence linter */
	(void)dispatch_table, (void)filename, (void)file_ctx;

	free_pgp_list(list);
	init_pgp_list(list);

	return 0;
}
