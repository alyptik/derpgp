/*
 * packet.h: packet mpi_data parsing and handling functions
 *
 * AUTHORS:	Joey Pabalinas <alyptik@protonmail.com>
 *		Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#ifndef _PACKET_H
#define _PACKET_H 1

#include "errs.h"
#include "defs.h"
#include <limits.h>
#include <stdint.h>
#include <unistd.h>

/* prototypes */
size_t parse_pubkey_packet(pgp_packet *packet);
size_t parse_seckey_packet(pgp_packet *packet);

static inline size_t read_mpi(u8 *mpi_buf, mpi *mpi_ptr) {

	mpi_ptr->length = HTOLE16(mpi_buf);

	size_t byte_length = (mpi_ptr->length + 1) / 8;

	xmalloc(&mpi_ptr->mdata, sizeof *mpi_ptr->mdata * byte_length, "read_mpi()");
	memcpy(mpi_ptr->mdata, mpi_buf + 2, byte_length);

	return 2 + byte_length;
}

#endif
