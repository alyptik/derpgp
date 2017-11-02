/*
 * parse.c:	option parsing
 *
 * AUTHORS:	Joey Pabalinas <alyptik@protonmail.com>
 *		Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#include "parse.h"

/* silence linter */
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int munmap(void *addr, size_t length);

size_t read_pgp_bin(char const *restrict filename, pgp_list *restrict list)
{
	FILE *file;
	pgp_packet cur;
	size_t cnt = 0;

	if (!list)
		ERR("read_pgp_bin() NULL pgp_list");

	free_pgp_list(list);
	init_pgp_list(list);
	if (!(file = fopen(filename, "rb")))
		ERR("read_pgp_bin() fopen()");

	if ((cnt += fread(&cur.pheader, 1, sizeof cur.pheader, file)) == 0) {
		fclose(file);
		return cnt;
	}

	if ((cur.pheader & (0x03 << 6)) & F_OLD) {
		switch (cur.pheader & 0x03) {
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

		case L_TWO:
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

		case L_FOUR:
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

		case L_OTHER: /* fallthrough */
		default:;
		}
	}

	fclose(file);
	return cnt;
}

size_t read_pgp_aa(char const *restrict filename, pgp_list *restrict list)
{
	(void)filename;
	free_pgp_list(list);
	init_pgp_list(list);

	return 0;
}
