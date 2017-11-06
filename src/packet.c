/*
 * packet.c:	option parsing
 *
 * AUTHORS:	Joey Pabalinas <alyptik@protonmail.com>
 *		Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#include "packet.h"

/* extern inline prototypes to prevent linker errors */
extern inline size_t read_mpi(u8 *restrict mpi_buf, mpi *restrict mpi_ptr);

size_t parse_pubkey_packet(pgp_packet *restrict packet)
{
	/*
	 * FIXME: we only support version 4, so bail if the
	 * version identifier is any different.
	 */
	assert(packet->pdata[0] == 4);

	packet->pubkey.version = 4;
	packet->pubkey.timestamp = BETOH32(packet->pdata + 1);
	packet->pubkey.algorithm = packet->pdata[5];
	assert(packet->pubkey.algorithm == 1);

	mpi tmp;
	ptrdiff_t mpi_offset = 6;
	tmp.length = BETOH16(packet->pdata + mpi_offset);
	mpi_offset += read_mpi(packet->pdata + mpi_offset, &tmp);
	packet->pubkey.modulus_n = tmp;
	mpi_offset += read_mpi(packet->pdata + mpi_offset, &tmp);
	packet->pubkey.exponent = tmp;

	return mpi_offset;
}


size_t parse_seckey_packet(pgp_packet *restrict packet)
{
	(void) packet;
	puts("Ayylmao");

	return 0;
}
