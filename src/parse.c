/*
 * parse.c:	option parsing
 *
 * AUTHORS:	Joey Pabalinas <alyptik@protonmail.com>
 *		Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#include "parse.h"

/* read binary pgp format */
size_t read_pgp_bin(char const *restrict filename, pgp_list *restrict list)
{
	FILE *file;
	pgp_packet cur;
	size_t cnt = 0;

	if (!list)
		ERR("read_pgp_bin() NULL pgp_list");
	free_pgp_list(list);
	init_pgp_list(list);

	/* read the header */
	if (!(file = fopen(filename, "rb")))
		ERR("read_pgp_bin() fopen()");
	if ((cnt += fread(&cur.pheader, 1, sizeof cur.pheader, file)) == 0) {
		fclose(file);
		return cnt;
	}

	/* old format header */
	if ((cur.pheader & (0x03 << 6)) == F_OLD) {
		switch (cur.pheader & 0x03) {
		/* one byte length */
		case L_ONE:
			if ((cnt += fread(&cur.plen_one, 1, sizeof cur.plen_one, file)) == 0) {
				fclose(file);
				ERR("unknown file format");
			}
			if (!(cur.pdata = calloc(cur.plen_one, sizeof *cur.pdata))) {
				fclose(file);
				ERR("read_pgp() cur.plen_one calloc()");
			}
			if ((cnt += fread(&cur.pdata, 1, cur.plen_one, file)) == 0) {
				fclose(file);
				ERR("unknown file format");
			}
			break;

		/* two byte length */
		case L_TWO:
			if ((cnt += fread(&cur.plen_two, 1, sizeof cur.plen_two, file)) == 0) {
				fclose(file);
				ERR("unknown file format");
			}
			if (!(cur.pdata = calloc(cur.plen_two, sizeof *cur.pdata))) {
				fclose(file);
				ERR("read_pgp() cur.plen_two calloc()");
			}
			if ((cnt += fread(&cur.pdata, 1, cur.plen_two, file)) == 0) {
				fclose(file);
				ERR("unknown file format");
			}
			break;

		/* four byte length */
		case L_FOUR:
			if ((cnt += fread(&cur.plen_four, 1, sizeof cur.plen_four, file)) == 0) {
				fclose(file);
				ERR("unknown file format");
			}
			if (!(cur.pdata = calloc(cur.plen_four, sizeof *cur.pdata))) {
				fclose(file);
				ERR("read_pgp() cur.plen_four calloc()");
			}
			if ((cnt += fread(&cur.pdata, 1, cur.plen_four, file)) == 0) {
				fclose(file);
				ERR("unknown file format");
			}
			break;

		/* TODO XXX: add handling for indeterminate packet length */
		case L_OTHER: /* fallthrough */
		default:;
		}

	/* new format header */
	} else if ((cur.pheader & (0x03 << 6)) == F_NEW) {
		/* TODO XXX: implement new format header handling */

	/* unknown header */
	} else {
		fclose(file);
		ERR("unknown file format");
	}

	fclose(file);
	return cnt;
}

/* read ascii armor pgp format */
size_t read_pgp_aa(char const *restrict filename, pgp_list *restrict list)
{
	(void)filename;
	free_pgp_list(list);
	init_pgp_list(list);

	return 0;
}
