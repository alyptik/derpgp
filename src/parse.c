/*
 * parse.c:	pgp key parsing
 *
 * AUTHORS:	Joey Pabalinas <alyptik@protonmail.com>
 *		Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#include "parse.h"

/* extern inline prototypes to prevent linker errors */
extern inline size_t free_pubkey_packet(PGP_PACKET *restrict packet);
extern inline size_t free_seckey_packet(PGP_PACKET *restrict packet);
extern inline void free_pgp_list(PGP_LIST *restrict pkts);
extern inline void init_pgp_list(PGP_LIST *restrict list_struct);
extern inline void add_pgp_list(PGP_LIST *restrict list_struct, PGP_PACKET const *restrict packet);
extern inline size_t read_pgp_bin(FILE *file_ctx, char const *restrict filename, PGP_LIST *restrict list);

/*
 * static function pointer array
 *
 * TODO XXX: implement remaining handlers
 */
size_t (*const dispatch_table[64][2])(PGP_PACKET *restrict) = {
	[T_RSRVD] = {0},
	[T_PKESESS] = {0},
	[T_SIG] = {0},
	[T_SKESESS] = {0},
	[T_OPSIG] = {0},
	[T_SECKEY] = {&parse_seckey_packet, &free_seckey_packet},
	[T_PUBKEY] = {&parse_pubkey_packet, &free_pubkey_packet},
	[T_SECSUBKEY] = {0},
	[T_CDATA] = {0},
	[T_SEDATA] = {0},
	[T_MARKER] = {0},
	[T_LITDATA] = {0},
	[T_TRUST] = {0},
	[T_UID] = {0},
	[T_PUBSUBKEY] = {0},
	[T_UATTR] = {0},
	[T_SEIPDATA] = {0},
	[T_MDCODE] = {0},
	[T_PRVT0] = {0},
	[T_PRVT1] = {0},
	[T_PRVT2] = {0},
	[T_PRVT3] = {0},
};

/* dispatch each packet to a parser */
size_t parse_pgp_packets(PGP_LIST *restrict pkts)
{
	size_t i = 0;
	if (!pkts)
		ERRX("NULL list passed to parse_pgp_packets()");
	for (i = 0; i < pkts->cnt; i++) {
		int packet_type = (pkts->list[i].pheader & 0x3c) >> 2;
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
