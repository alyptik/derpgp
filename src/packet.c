/*
 * packet.c:	mpi_data parsing and handling functions
 *
 * AUTHORS:	Joey Pabalinas <alyptik@protonmail.com>
 *		Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#include "packet.h"

size_t parse_pubkey_packet(PGP_PACKET *restrict packet)
{
	/*
	 * FIXME: we only support version 4, so bail if the
	 * version identifier is any different.
	 */
	MPI tmp = {0};
	size_t mpi_offset = 0;

	/* one byte */
	packet->pubkey.version = packet->pdata[mpi_offset];
	assert(packet->pubkey.version == 4);
	mpi_offset++;
	/* four bytes */
	packet->pubkey.timestamp = BETOH32(packet->pdata + mpi_offset);
	mpi_offset += 4;
	/* one byte */
	packet->pubkey.algorithm = packet->pdata[mpi_offset];
	assert(packet->pubkey.algorithm == PUB_RSA);
	mpi_offset++;
	/* one mpi struct */
	tmp.length = BETOH16(packet->pdata + mpi_offset);
	mpi_offset += read_mpi(packet->pdata + mpi_offset, &tmp);
	packet->pubkey.modulus_n = tmp;
	/* one mpi struct */
	tmp = (MPI){0};
	mpi_offset += read_mpi(packet->pdata + mpi_offset, &tmp);
	packet->pubkey.exponent = tmp;

	return mpi_offset;
}

size_t parse_seckey_packet(PGP_PACKET *restrict packet)
{
	size_t mpi_offset = 0;

	/* one byte */
	packet->seckey.string_to_key = packet->pdata[mpi_offset];
	mpi_offset++;

	/* debug printing */
	HPRINT(packet->seckey.string_to_key);

	/* string-to-key usage convention */
	switch (packet->seckey.string_to_key) {
	/* unencrypted */
	case STR_RAW:
		break;
	/* s2k specifier */
	case STR_S2K1: /* fallthrough */
	case STR_S2K2:
		/* one byte */
		packet->seckey.sym_encryption_algo = packet->pdata[mpi_offset];
		mpi_offset++;
		/* TODO XXX: implement rest of s2k handling */
		printf(YELLOW "%s\n" RST, s2k_types[packet->seckey.string_to_key]);
		break;
	/* symmetric-key algorithm */
	default:
		/* TODO XXX: implement symmetric-key handling */
		printf(YELLOW "%s\n" RST, symkey_types[packet->seckey.string_to_key]);
		break;
	}

	/* TODO XXX: implement mpi seckey parsing */

	return mpi_offset;
}
