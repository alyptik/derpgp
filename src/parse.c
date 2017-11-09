/*
 * parse.c:	pgp key parsing
 *
 * AUTHORS:	Joey Pabalinas <alyptik@protonmail.com>
 *		Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#include "parse.h"

/* dispatch each packet to a parser */
size_t parse_pgp_packets(PGP_LIST *restrict pkts)
{
	size_t i = 0;

	/* dispatch each packet to parsers */
	for (; i < pkts->cnt; i++) {
		int packet_type = TAGBITS(pkts->list[i].pheader);
		size_t (*const parse)(PGP_PACKET *restrict) = dispatch_table[packet_type][0];
		if (parse)
			parse(&pkts->list[i]);
	}

	return i;
}

/* read ascii armor pgp format */
size_t read_pgp_aa(FILE *file_ctx, char const *restrict filename, PGP_LIST *restrict list)
{
	/* silence linter */
	(void)dispatch_table, (void)filename, (void)file_ctx;

	free_pgp_list(list);
	init_pgp_list(list);

	return 0;
}
