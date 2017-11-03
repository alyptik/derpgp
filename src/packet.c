/*
 * packet.c:	option parsing
 *
 * AUTHORS:	Joey Pabalinas <alyptik@protonmail.com>
 *		Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#include "packet.h"

size_t parse_pubkey_packet(pgp_packet *packet) {
	u8 *data = packet->pdata;

	// FIXME: we only support version 4, so bail if the version identifier is
	// any different.
	assert(data[0] == 4);

	packet->pubkey.version = 4;
	packet->pubkey.timestamp = HTOLE32(data + 1);
	packet->pubkey.algorithm = data[5];

	assert(packet->pubkey.algorithm == 1);

	unsigned int mpi_offset = 6;
	MPI this_mpi;
	this_mpi.length = HTOLE16(data + mpi_offset);
	mpi_offset += read_mpi(data + mpi_offset, &this_mpi);

	packet->pubkey.modulus_n = this_mpi;
	mpi_offset += read_mpi(data + mpi_offset, &this_mpi);

	packet->pubkey.exponent = this_mpi;

	return 0;
}


size_t parse_seckey_packet(pgp_packet *packet) {
	puts("Ayylmao");
}
