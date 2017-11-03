/*
 * packet.h: packet data parsing and handling functions
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

static inline size_t read_mpi(u8 *buffer, MPI *mpi) {
	
	mpi->length = HTOLE16(buffer);

	size_t byte_length = (mpi->length + 1)/ 8;

	u8 *data = (u8 *)malloc(sizeof(*data) * byte_length);
	memcpy(data, buffer + 2, byte_length);

	mpi->data = data;

	return 2 + byte_length;
}

#endif // muh include ward
