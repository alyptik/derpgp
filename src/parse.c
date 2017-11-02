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

size_t read_pgp_bin(char const *restrict filename, struct pgp_list *restrict list)
{
	(void)filename;
	free_pgp_list(list);
	init_pgp_list(list);

	return 0;
}

size_t read_pgp_aa(char const *restrict filename, struct pgp_list *restrict list)
{
	(void)filename;
	free_pgp_list(list);
	init_pgp_list(list);

	return 0;
}
