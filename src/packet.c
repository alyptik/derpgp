/*
 * packet.c:	option parsing
 *
 * AUTHORS:	Joey Pabalinas <alyptik@protonmail.com>
 *		Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#include "packet.h"

size_t parse_pubkey_packet(pgp_packet *restrict packet)
{
	/*
	 * FIXME: we only support version 4, so bail if the
	 * version identifier is any different.
	 */
	mpi tmp = {0};
	size_t mpi_offset = 0;

	/* one byte */
	packet->pubkey.version = packet->pdata[0];
	assert(packet->pubkey.version == 4);
	mpi_offset++;
	/* four bytes */
	packet->pubkey.timestamp = BETOH32(packet->pdata + mpi_offset);
	mpi_offset += 4;
	/* one byte */
	packet->pubkey.algorithm = packet->pdata[mpi_offset];
	assert(packet->pubkey.algorithm == 1);
	mpi_offset++;
	tmp.length = BETOH16(packet->pdata + mpi_offset);
	mpi_offset += read_mpi(packet->pdata + mpi_offset, &tmp);
	/* one mpi struct */
	packet->pubkey.modulus_n = tmp;
	mpi_offset += read_mpi(packet->pdata + mpi_offset, &tmp);
	/* one mpi struct */
	packet->pubkey.exponent = tmp;

	return mpi_offset;
}


size_t parse_seckey_packet(pgp_packet *restrict packet)
{
	(void)packet;
	puts("Ayylmao");

	return 0;
}
