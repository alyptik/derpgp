/*
 * parse.h:	header for parse.c
 *
 * AUTHORS:	Joey Pabalinas <alyptik@protonmail.com>
 *		Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#ifndef _PARSE_H
#define _PARSE_H 1

#include "defs.h"
#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/memfd.h>
#include <math.h>
#include <regex.h>
#include <signal.h>
#include <stdalign.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <uchar.h>
#include <unistd.h>
#include <wchar.h>

size_t read_pgp_bin(FILE *restrict file_ctx, char const *restrict filename, pgp_list *restrict list);
size_t read_pgp_aa(FILE *restrict file_ctx, char const *restrict filename, pgp_list *restrict list);

static inline void free_pgp_list(pgp_list *restrict list_struct)
{
	/* return if passed NULL pointers */
	if (!list_struct || !list_struct->list)
		return;
	for (size_t i = 0; i < list_struct->cnt; i++)
		free(list_struct->list[i].pdata);
	free(list_struct->list);
	list_struct->list = NULL;
	list_struct->cnt = 0;
	list_struct->max = 1;
}

static inline void init_pgp_list(pgp_list *restrict list_struct)
{
	list_struct->cnt = 0;
	list_struct->max = 1;
	xcalloc(&list_struct->list, 1, sizeof *list_struct->list, "error during initial list_ptr calloc()");
}

static inline void add_pgp_list(pgp_list *restrict list_struct, pgp_packet const *restrict packet)
{
	list_struct->cnt++;
	/* realloc if cnt reaches current size */
	if (list_struct->cnt >= list_struct->max) {
		/* check if size too large */
		if (list_struct->cnt > ARRAY_MAX)
			ERRX("list_struct->cnt > (SIZE_MAX / 2 - 1)");
		list_struct->max *= 2;
		xrealloc(&list_struct->list, sizeof *list_struct->list * list_struct->max, "append_packet()");
	}
	list_struct->list[list_struct->cnt - 1] = *packet;
}

#endif
