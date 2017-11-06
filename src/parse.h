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

size_t read_pgp_aa(FILE *file_ctx, char const *restrict filename, pgp_list *restrict list);

inline void free_pgp_list(pgp_list *restrict list_struct)
{
	/* return if passed NULL pointers */
	if (!list_struct || !list_struct->list)
		return;
	for (size_t i = 0; i < list_struct->cnt; i++) {
		/* TODO XXX: use better `free()` strategy */
		switch ((list_struct->list[i].pheader & 0x3c) >> 2) {
		case T_PUBKEY:
			free(list_struct->list[i].pubkey.modulus_n.mdata);
			free(list_struct->list[i].pubkey.exponent.mdata);
			break;
		case T_SECKEY:
			free(list_struct->list[i].seckey.exponent_d.mdata);
			free(list_struct->list[i].seckey.mult_inverse.mdata);
			free(list_struct->list[i].seckey.prime_p.mdata);
			free(list_struct->list[i].seckey.prime_q.mdata);
			break;
		}
		free(list_struct->list[i].pdata);
	}
	free(list_struct->list);
	list_struct->list = NULL;
	list_struct->cnt = 0;
	list_struct->max = 1;
}

inline void init_pgp_list(pgp_list *restrict list_struct)
{
	list_struct->cnt = 0;
	list_struct->max = 1;
	xcalloc(&list_struct->list, 1, sizeof *list_struct->list, "error during initial list_ptr calloc()");
}

inline void add_pgp_list(pgp_list *restrict list_struct, pgp_packet const *restrict packet)
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

/* read binary pgp format */
inline size_t read_pgp_bin(FILE *file_ctx, char const *restrict filename, pgp_list *restrict list)
{
	FILE *file = file_ctx;
	pgp_packet cur = {0};

	/* sanity checks */
	if (!file) {
		free_pgp_list(list);
		init_pgp_list(list);
		/* read the header */
		if (!(file = fopen(filename, "rb")))
			ERR("read_pgp_bin() fopen()");
	}

	/* read header byte */
	if (!xfread(&cur.pheader, 1, sizeof cur.pheader, file))
		goto BASE_CASE;

	/* header type */
	switch ((cur.pheader & (0x01 << 6)) >> 6) {
	/* old format header */
	case F_OLD:
		/* header length */
		switch (cur.pheader & 0x03) {
		/* one byte length */
		case L_ONE:
			if (!xfread(&cur.plen_raw, 1, sizeof cur.plen_one, file))
				goto BASE_CASE;
			cur.plen_one = cur.plen_raw[0];
			xcalloc(&cur.pdata, cur.plen_one, sizeof *cur.pdata, "read_pgp() cur.plen_one calloc()");
			if (!xfread(cur.pdata, 1, cur.plen_one, file))
				goto BASE_CASE;
			break;

		/* two byte length */
		case L_TWO:
			if (!xfread(&cur.plen_raw, 1, sizeof cur.plen_two, file))
				goto BASE_CASE;
			cur.plen_two = BETOH16(cur.plen_raw);
			xcalloc(&cur.pdata, cur.plen_two, sizeof *cur.pdata, "read_pgp() cur.plen_two calloc()");
			if (!xfread(cur.pdata, 1, cur.plen_two, file))
				goto BASE_CASE;
			break;

		/* four byte length */
		case L_FOUR:
			if (!xfread(&cur.plen_raw, 1, sizeof cur.plen_four, file))
				goto BASE_CASE;
			cur.plen_four = BETOH32(cur.plen_raw);
			xcalloc(&cur.pdata, cur.plen_four, sizeof *cur.pdata, "read_pgp() cur.plen_four calloc()");
			if (!xfread(cur.pdata, 1, cur.plen_four, file))
				goto BASE_CASE;
			break;

		/*
		 * indeterminate length
		 *
		 * TODO XXX: add handling for indeterminate packet length
		 */
		case L_OTHER: /* fallthrough */
		default:
			goto BASE_CASE;
		}
		break;

	/*
	 * new format header
	 *
	 * TODO XXX: implement new format header handling
	 */
	case F_NEW: /* fallthrough */
	/* unrecognized header */
	default:
		goto BASE_CASE;
	}

	/* recurse */
	add_pgp_list(list, &cur);
	return read_pgp_bin(file, filename, list);

/* base case common exit point */
BASE_CASE:
	fclose(file);
	return list->cnt;
}

#endif
