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
	packet->seckey.der.modulus_n = &packet->seckey.modulus_n;
	/* one mpi struct */
	mpi_offset += read_mpi(packet->pdata + mpi_offset, &packet->seckey.exponent_e);
	packet->seckey.der.exponent_e = &packet->seckey.exponent_e;

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
		packet->seckey.der.exponent_d = &packet->seckey.exponent_d;
		printf(RED "[MPI length: %#4x] " RST, packet->seckey.exponent_d.length);

		/* one mpi struct */
		mpi_offset += read_mpi(packet->pdata + mpi_offset, &packet->seckey.prime_p);
		packet->seckey.der.prime_p = &packet->seckey.prime_p;
		printf(RED "[MPI length: %#4x] " RST, packet->seckey.prime_p.length);

		/* one mpi struct */
		mpi_offset += read_mpi(packet->pdata + mpi_offset, &packet->seckey.prime_q);
		packet->seckey.der.prime_q = &packet->seckey.prime_q;
		printf(RED "[MPI length: %#4x] " RST, packet->seckey.prime_q.length);

		/* one mpi struct */
		mpi_offset += read_mpi(packet->pdata + mpi_offset, &packet->seckey.mult_inverse);
		packet->seckey.der.mult_inverse = &packet->seckey.mult_inverse;
		printf(RED "[MPI length: %#4x]\n" RST, packet->seckey.mult_inverse.length);

		/* encode the DER representation */
		der_encode(packet);
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

	/* TODO XXX: implement mpi secret key parsing */

	return mpi_offset;
}

size_t der_encode(PGP_PACKET *restrict packet)
{
	u8 const header[2] = {0x30, 0x82};
	/* version header bytes `0x02, 0x01, 0x00` for INTEGER, SIZE 1, DATA */
	packet->seckey.der.version[0] = 0x02;
	packet->seckey.der.version[1] = 0x01;
	packet->seckey.der.version[2] = 0x00;
	size_t der_offset = 0;

	/* get total length */

	packet->seckey.der.der_len = sizeof header;
	packet->seckey.der.der_len += sizeof packet->seckey.der.version;
	packet->seckey.der.der_len += MPIBYTES(packet->seckey.der.modulus_n->length);
	packet->seckey.der.der_len += MPIBYTES(packet->seckey.der.exponent_e->length);
	packet->seckey.der.der_len += MPIBYTES(packet->seckey.der.exponent_d->length);
	packet->seckey.der.der_len += MPIBYTES(packet->seckey.der.prime_p->length);
	packet->seckey.der.der_len += MPIBYTES(packet->seckey.der.prime_q->length);
	/*
	 * TODO: implement dP and dQ calculation
	 *
	 * packet->seckey.der.der_len += MPIBYTES(packet->seckey.der.exponent_dP->length);
	 * packet->seckey.der.der_len += MPIBYTES(packet->seckey.der.exponent_dQ->length);
	 */
	packet->seckey.der.der_len += MPIBYTES(packet->seckey.der.mult_inverse->length);
	/* add space for MPI length bytes */
	packet->seckey.der.der_len += DER_TOTAL_LEN;

	/* allocate the DER data octet string data */
	xcalloc(&packet->seckey.der.der_data, 1, packet->seckey.der.der_len, "der_encode() xcalloc()");

	/* header */
	memcpy(packet->seckey.der.der_data + der_offset, header, sizeof header);
	der_offset += sizeof header;
	/* version */
	memcpy(packet->seckey.der.der_data + der_offset,
			packet->seckey.der.version, sizeof packet->seckey.der.version);
	der_offset += sizeof packet->seckey.der.version;

	/* modulus_n */
	memcpy(packet->seckey.der.der_data + der_offset, packet->seckey.der.modulus_n->be_len, 2);
	der_offset += 2;
	memcpy(packet->seckey.der.der_data + der_offset,
			packet->seckey.der.modulus_n->mdata, MPIBYTES(packet->seckey.der.modulus_n->length));
	der_offset += MPIBYTES(packet->seckey.der.modulus_n->length);

	/* exponent_e */
	memcpy(packet->seckey.der.der_data + der_offset, packet->seckey.der.exponent_e->be_len, 2);
	der_offset += 2;
	memcpy(packet->seckey.der.der_data + der_offset,
			packet->seckey.der.exponent_e->mdata, MPIBYTES(packet->seckey.der.exponent_e->length));
	der_offset += MPIBYTES(packet->seckey.der.exponent_e->length);
	/* exponent_d */
	memcpy(packet->seckey.der.der_data + der_offset, packet->seckey.der.exponent_d->be_len, 2);
	der_offset += 2;
	memcpy(packet->seckey.der.der_data + der_offset,
			packet->seckey.der.exponent_d->mdata, MPIBYTES(packet->seckey.der.exponent_d->length));
	der_offset += MPIBYTES(packet->seckey.der.exponent_d->length);

	/* prime_p */
	memcpy(packet->seckey.der.der_data + der_offset, packet->seckey.der.prime_p->be_len, 2);
	der_offset += 2;
	memcpy(packet->seckey.der.der_data + der_offset,
			packet->seckey.der.prime_p->mdata, MPIBYTES(packet->seckey.der.prime_p->length));
	der_offset += MPIBYTES(packet->seckey.der.prime_p->length);
	/* prime_q */
	memcpy(packet->seckey.der.der_data + der_offset, packet->seckey.der.prime_q->be_len, 2);
	der_offset += 2;
	memcpy(packet->seckey.der.der_data + der_offset,
			packet->seckey.der.prime_q->mdata, MPIBYTES(packet->seckey.der.prime_q->length));
	der_offset += MPIBYTES(packet->seckey.der.prime_q->length);

	/*
	 * TODO: implement dP and dQ calculation
	 */
	/* exponent_dP */
	/*
	 * memcpy(packet->seckey.der.der_data + der_offset, HTOBE16(packet->seckey.der.exponent_dP->length), 2);
	 * der_offset += 2;
	 * memcpy(packet->seckey.der.der_data + der_offset,
	 *                 packet->seckey.exponent_dP.mdata, MPIBYTES(packet->seckey.der.exponent_dP->length));
	 * der_offset += MPIBYTES(packet->seckey.der.exponent_dP->length);
	 */
	/* exponent_dQ */
	/*
	 * memcpy(packet->seckey.der.der_data + der_offset, HTOBE16(packet->seckey.der.exponent_dQ->length), 2);
	 * der_offset += 2;
	 * memcpy(packet->seckey.der.der_data + der_offset,
	 *                 packet->seckey.exponent_dQ.mdata, MPIBYTES(packet->seckey.der.exponent_dQ->length));
	 * der_offset += MPIBYTES(packet->seckey.der.exponent_dQ->length);
	 */

	/* mult_inverse */
	memcpy(packet->seckey.der.der_data + der_offset, packet->seckey.der.mult_inverse->be_len, 2);
	der_offset += 2;
	memcpy(packet->seckey.der.der_data + der_offset,
			packet->seckey.der.mult_inverse->mdata, MPIBYTES(packet->seckey.der.mult_inverse->length));
	der_offset += MPIBYTES(packet->seckey.der.mult_inverse->length);

	assert(packet->seckey.der.der_len == der_offset);

	return der_offset;
}
