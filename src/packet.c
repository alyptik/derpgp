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
	u8 *pub_data = packet->pdata;

	// FIXME: we only support version 4, so bail if the version identifier is
	// any different.
	assert(pub_data[0] == 4);

	packet->pubkey.version = 4;
	packet->pubkey.timestamp = HTOLE32(pub_data + 1);
	packet->pubkey.algorithm = pub_data[5];

	assert(packet->pubkey.algorithm == 1);

	ptrdiff_t mpi_offset = 6;
	mpi tmp;
	tmp.length = HTOLE16(pub_data + mpi_offset);
	mpi_offset += read_mpi(pub_data + mpi_offset, &tmp);

	packet->pubkey.modulus_n = tmp;
	mpi_offset += read_mpi(pub_data + mpi_offset, &tmp);

	(void)mpi_offset;

	packet->pubkey.exponent = tmp;

	return 1;
}


size_t parse_seckey_packet(pgp_packet *packet) {
	(void) packet;
	puts("Ayylmao");
	return 0;
}
