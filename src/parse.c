/*
 * parse.c:	option parsing
 *
 * AUTHORS:	Joey Pabalinas <alyptik@protonmail.com>
 *		Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#include "parse.h"

/* static function pointer array */
/*
 * static packet_handler dispatch_table[64] = {
 *          parse_rsrvd, parse_pkesess, parse_skesess,
 *          parse_opsig, parse_seckey, parse_pubkey,
 *          parse_cdata, parse_secsubkey, parse_sedat,
 *          parse_marker, parse_litdata, parse_trust,
 *          parse_ui, parse_pubsubkey, 0, 0,
 *          parse_uattr, parse_seipdata, parse_mdcode,
 *          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
 *          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
 *          parse_prvt0, parse_prvt1, parse_prvt2, parse_prvt3,
 * }
 */

/* read binary pgp format */
size_t read_pgp_bin(FILE *restrict file_ctx, char const *restrict filename, pgp_list *restrict list)
{
	/* silence linter */
	/* (void)dispatch_table; */

	FILE *file;
	pgp_packet cur = {0};

	if (!list)
		ERR("read_pgp_bin() NULL pgp_list");
	if (!file_ctx) {
		free_pgp_list(list);
		init_pgp_list(list);
		/* read the header */
		if (!(file = fopen(filename, "rb")))
			ERR("read_pgp_bin() fopen()");
	} else {
		file = file_ctx;
	}

	if (!xfread(&cur.pheader, 1, sizeof cur.pheader, file)) {
		fclose(file);
		return list->cnt;
	}

	/* header type */
	switch ((cur.pheader & (0x01 << 6)) >> 6) {
	/* old format header */
	case F_OLD:
		/* header length */
		switch (cur.pheader & 0x03) {
		/* one byte length */
		case L_ONE:
			if (!xfread(&cur.plen_raw, sizeof cur.plen_one, 1, file)) {
				fclose(file);
				return list->cnt;
			}
			cur.plen_one = cur.plen_raw[0];
			xcalloc(&cur.pdata, cur.plen_one, sizeof *cur.pdata, "read_pgp() cur.plen_one calloc()");
			if (!xfread(cur.pdata, cur.plen_one, 1, file)) {
				fclose(file);
				return list->cnt;
			}
			break;

		/* two byte length */
		case L_TWO:
			if (!xfread(&cur.plen_raw, sizeof cur.plen_two, 1, file)) {
				fclose(file);
				return list->cnt;
			}
			cur.plen_two = HTOLE16(cur.plen_raw);
			xcalloc(&cur.pdata, cur.plen_two, sizeof *cur.pdata, "read_pgp() cur.plen_two calloc()");
			if (!xfread(cur.pdata, cur.plen_two, 1, file)) {
				fclose(file);
				return list->cnt;
			}
			break;

		/* four byte length */
		case L_FOUR:
			if (!xfread(&cur.plen_raw, sizeof cur.plen_four, 1, file)) {
				fclose(file);
				return list->cnt;
			}
			cur.plen_four = HTOLE32(cur.plen_raw);
			xcalloc(&cur.pdata, cur.plen_four, sizeof *cur.pdata, "read_pgp() cur.plen_four calloc()");
			if (!xfread(cur.pdata, cur.plen_four, 1, file)) {
				fclose(file);
				return list->cnt;
			}
			break;

		/* indeterminate length */
		/* TODO XXX: add handling for indeterminate packet length */
		case L_OTHER: /* fallthrough */
		default:
			fclose(file);
			return list->cnt;
		}
		break;

	/* new format header */
	/* TODO XXX: implement new format header handling */
	case F_NEW:
		fclose(file);
		return list->cnt;
		break;

	/* unrecognized header */
	default:
		fclose(file);
		return list->cnt;
	}

	add_pgp_list(list, &cur);
	return read_pgp_bin(file, filename, list);
}

/* read ascii armor pgp format */
size_t read_pgp_aa(FILE *restrict file_ctx, char const *restrict filename, pgp_list *restrict list)
{
	(void)filename, (void)file_ctx;
	free_pgp_list(list);
	init_pgp_list(list);

	return 0;
}
