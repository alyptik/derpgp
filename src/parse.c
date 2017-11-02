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

struct pgp_packet *read_pgp_bin(char const *filename)
{
	(void)filename;

	return NULL;
}

struct pgp_packet *read_pgp_aa(char const *filename)
{
	(void)filename;

	return NULL;
}
