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

/* dispatch each packet to a parser */
size_t parse_pgp_packets(pgp_list *restrict pkts)
{
	size_t i = 0;
	if (!pkts)
		ERRX("NULL list passed to parse_pgp_packets()");
	for (i = 0; i < pkts->cnt; i++) {
		int packet_type = (pkts->list[i].pheader & 0x3c) >> 2;
		int (*const parser)() = dispatch_table[packet_type];
		if (parser)
			parser(&pkts->list[i]);
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
