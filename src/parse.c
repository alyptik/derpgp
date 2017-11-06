/*
 * parse.c:	option parsing
 *
 * AUTHORS:	Joey Pabalinas <alyptik@protonmail.com>
 *		Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#include "parse.h"

/*
 * static function pointer array
 *
 * TODO XXX: implement handlers
 */
static int (*const dispatch_table[]) = {
	/* parse_rsrvd, parse_pkesess, parse_skesess, */
	0, 0, 0,
	/* parse_opsig, parse_seckey, parse_pubkey, */
	0, 0, 0,
	/* parse_cdata, parse_secsubkey, parse_sedat, */
	0, 0, 0,
	/* parse_marker, parse_litdata, parse_trust, */
	0, 0, 0,
	/* parse_ui, parse_pubsubkey, */
	0, 0, 0,
	/* two placeholder indices */
	0, 0,
	/* parse_uattr, parse_seipdata, parse_mdcode, */
	0, 0, 0,
	/* ten placeholder indices */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* ten placeholder indices */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* parse_prvt0, parse_prvt1, parse_prvt2, parse_prvt3, */
	0, 0, 0, 0,
};

/* extern inline prototypes to prevent linker errors */
extern inline void free_pgp_list(pgp_list *restrict list_struct);
extern inline void init_pgp_list(pgp_list *restrict list_struct);
extern inline void add_pgp_list(pgp_list *restrict list_struct, pgp_packet const *restrict packet);
extern inline size_t read_pgp_bin(FILE *file_ctx, char const *restrict filename, pgp_list *restrict list);

/* read ascii armor pgp format */
size_t read_pgp_aa(FILE *file_ctx, char const *restrict filename, pgp_list *restrict list)
{
	/* silence linter */
	(void)dispatch_table, (void)filename, (void)file_ctx;

	free_pgp_list(list);
	init_pgp_list(list);

	return 0;
}
