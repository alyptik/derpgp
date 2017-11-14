/*
 * packet.h:	header to packet.c
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

/* prototypes */
size_t parse_pubkey_packet(PGP_PACKET *restrict packet);
size_t parse_seckey_packet(PGP_PACKET *restrict packet);
size_t der_encode(PGP_PACKET *restrict packet);

static inline size_t read_mpi(u8 *restrict mpi_buf, MPI *restrict mpi_ptr)
{
	size_t byte_length;

	mpi_ptr->length = BETOH16(mpi_buf);
	/* convert bit-length to size in bytes */
	byte_length = MPIBYTES(mpi_ptr->length);
	xmalloc(&mpi_ptr->mdata, sizeof *mpi_ptr->mdata * byte_length, "read_mpi()");
	memcpy(mpi_ptr->mdata, mpi_buf + 2, byte_length);
	/*
	 * check MPI validity by right-shifting the first
	 * octet to make sure the non-value bits are 0
	 */
	assert((mpi_ptr->mdata[0] >> (FALLBACK((mpi_ptr->length % 8), 8))) == 0);

	return byte_length + 2;
}

#endif
