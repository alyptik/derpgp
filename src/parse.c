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
extern inline size_t free_pubkey_packet(pgp_packet *restrict packet);
extern inline size_t free_seckey_packet(pgp_packet *restrict packet);
extern inline void free_pgp_list(pgp_list *restrict pkts);
extern inline void init_pgp_list(pgp_list *restrict list_struct);
extern inline void add_pgp_list(pgp_list *restrict list_struct, pgp_packet const *restrict packet);
extern inline size_t read_pgp_bin(FILE *file_ctx, char const *restrict filename, pgp_list *restrict list);

/*
 * static function pointer array
 *
 * TODO XXX: implement remaining handlers
 */
size_t (*const dispatch_table[64][2])(pgp_packet *restrict) = {
	/*
	 * {&parse_rsrvd_packet, &free_rsrvd_packet},
	 * {&parse_pkesess_packet, &free_pkesess_packet},
	 * {&parse_skesess_packet, &free_skesess_packet},
	 */
	{0}, {0}, {0},
	/*
	 * {&parse_opsig_packet, &free_opsig_packet},
	 * {&parse_seckey_packet, &free_seckey_packet},
	 * {&parse_pubkey_packet, &free_pubkey_packet},
	 */
	{0},
	{&parse_seckey_packet, &free_seckey_packet},
	{&parse_pubkey_packet, &free_pubkey_packet},
	/*
	 * {&parse_cdata_packet, &free_cdata_packet},
	 * {&parse_secsubkey_packet, &free_secsubkey_packet},
	 * {&parse_sedat_packet, &free_sedat_packet},
	 */
	{0}, {0}, {0},
	/*
	 * {&parse_marker_packet, &free_marker_packet},
	 * {&parse_litdata_packet, &free_litdata_packet},
	 * {&parse_trust_packet, &free_trust_packet},
	 */
	{0}, {0}, {0},
	/*
	 * {&parse_ui_packet, &free_ui_packet},
	 * {&parse_pubsubkey_packet, &free_pubsubkey_packet},
	 */
	{0}, {0},
	/* two placeholder indices */
	{0}, {0},
	/*
	 * {&parse_uattr_packet, &free_uattr_packet},
	 * {&parse_seipdata_packet, &free_seipdata_packet},
	 * {&parse_mdcode_packet, &free_mdcode_packet},
	 */
	{0}, {0}, {0},
	/* ten placeholder indices */
	{0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
	/* ten placeholder indices */
	{0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
	/*
	 * {&parse_prvt0_packet, &free_prvt0_packet},
	 * {&parse_prvt1_packet, &free_prvt1_packet},
	 * {&parse_prvt2_packet, &free_prvt2_packet},
	 * {&parse_prvt3_packet, &free_prvt3_packet},
	 */
	{0}, {0}, {0}, {0},
};

/* dispatch each packet to a parser */
size_t parse_pgp_packets(pgp_list *restrict pkts)
{
	size_t i = 0;
	if (!pkts)
		ERRX("NULL list passed to parse_pgp_packets()");
	for (i = 0; i < pkts->cnt; i++) {
		int packet_type = (pkts->list[i].pheader & 0x3c) >> 2;
		size_t (*const parse)(pgp_packet *restrict) = dispatch_table[packet_type][0];
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
