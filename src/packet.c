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
	mpi_offset += read_mpi(packet->pdata + mpi_offset, &packet->pubkey.modulus_n);
	/* one mpi struct */
	mpi_offset += read_mpi(packet->pdata + mpi_offset, &packet->pubkey.exponent_e);

	return mpi_offset;
}

size_t parse_seckey_packet(PGP_PACKET *restrict packet)
{
	/*
	 * parse public key portion of packet
	 */
	size_t mpi_offset = 0;

	/* allocate DER struct */
	xmalloc(&packet->seckey.der, sizeof *packet->seckey.der, "parse_seckey_packet() der struct");

	/* one byte */
	packet->seckey.version = packet->pdata[mpi_offset];
	assert(packet->seckey.version == 4);
	mpi_offset++;
	/* four bytes */
	packet->seckey.timestamp = BETOH32(packet->pdata + mpi_offset);
	mpi_offset += 4;
	/* one byte */
	packet->seckey.algorithm = packet->pdata[mpi_offset];
	assert(packet->seckey.algorithm == PUB_RSA);
	mpi_offset++;
	/* one mpi struct */
	mpi_offset += read_mpi(packet->pdata + mpi_offset, &packet->seckey.modulus_n);
	packet->seckey.der->modulus_n = packet->seckey.modulus_n;
	/* one mpi struct */
	mpi_offset += read_mpi(packet->pdata + mpi_offset, &packet->seckey.exponent_e);
	packet->seckey.der->exponent_e = packet->seckey.exponent_e;

	/*
	 * parse secret key portion of the packet
	 */

	/* one byte */
	packet->seckey.string_to_key = packet->pdata[mpi_offset];
	mpi_offset++;

	/* debug printing */
	HPRINT(packet->seckey.string_to_key);

	/* string-to-key usage convention */
	switch (packet->seckey.string_to_key) {
	/* unencrypted */
	case STR_RAW:
		printf(YELLOW "%s " RST, s2k_types[packet->seckey.string_to_key]);

		/* one mpi struct */
		mpi_offset += read_mpi(packet->pdata + mpi_offset, &packet->seckey.exponent_d);
		packet->seckey.der->exponent_d = packet->seckey.exponent_d;
		printf(RED "[MPI length: %#4x] " RST, packet->seckey.exponent_d.length);

		/* one mpi struct */
		mpi_offset += read_mpi(packet->pdata + mpi_offset, &packet->seckey.prime_p);
		packet->seckey.der->prime_p = packet->seckey.prime_p;
		printf(RED "[MPI length: %#4x] " RST, packet->seckey.prime_p.length);

		/* one mpi struct */
		mpi_offset += read_mpi(packet->pdata + mpi_offset, &packet->seckey.prime_q);
		packet->seckey.der->prime_q = packet->seckey.prime_q;
		printf(RED "[MPI length: %#4x] " RST, packet->seckey.prime_q.length);

		/* one mpi struct */
		mpi_offset += read_mpi(packet->pdata + mpi_offset, &packet->seckey.mult_inverse);
		packet->seckey.der->mult_inverse = packet->seckey.mult_inverse;
		printf(RED "[MPI length: %#4x]\n" RST, packet->seckey.mult_inverse.length);
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
