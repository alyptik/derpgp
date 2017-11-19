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
	packet->seckey.rsa.modulus_n = &packet->seckey.modulus_n;
	/* one mpi struct */
	mpi_offset += read_mpi(packet->pdata + mpi_offset, &packet->seckey.exponent_e);
	packet->seckey.rsa.exponent_e = &packet->seckey.exponent_e;

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
		packet->seckey.rsa.exponent_d = &packet->seckey.exponent_d;
		printf(RED "[MPI length: %#4x] " RST, packet->seckey.exponent_d.length);

		/* one mpi struct */
		mpi_offset += read_mpi(packet->pdata + mpi_offset, &packet->seckey.prime_p);
		packet->seckey.rsa.prime_p = &packet->seckey.prime_p;
		printf(RED "[MPI length: %#4x] " RST, packet->seckey.prime_p.length);

		/* one mpi struct */
		mpi_offset += read_mpi(packet->pdata + mpi_offset, &packet->seckey.prime_q);
		packet->seckey.rsa.prime_q = &packet->seckey.prime_q;
		printf(RED "[MPI length: %#4x] " RST, packet->seckey.prime_q.length);

		/* one mpi struct */
		mpi_offset += read_mpi(packet->pdata + mpi_offset, &packet->seckey.mult_inverse);
		packet->seckey.rsa.mult_inverse = &packet->seckey.mult_inverse;
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
	/* SEQUENCE, TWO LENGTH BYTES */
	u8 asn_seq[2] = {0x30, 0x82};
	u8 asn_int[2] = {0x02, 0x82};
	union { u8 raw[2]; u16 len; } header;
	/* version header bytes `0x02, 0x01, 0x00` for INTEGER, SIZE 1, DATA */
	packet->seckey.rsa.version[0] = 0x02;
	packet->seckey.rsa.version[1] = 0x01;
	packet->seckey.rsa.version[2] = 0x00;
	size_t der_offset = 0;

	/* get total length */

	packet->seckey.rsa.der_len = 0;
	packet->seckey.rsa.der_len += sizeof asn_seq;
	packet->seckey.rsa.der_len += sizeof header.raw;
	packet->seckey.rsa.der_len += sizeof packet->seckey.rsa.version;
	/* add space for MPI length bytes */
	packet->seckey.rsa.der_len += DER_TOTAL_LEN;
	packet->seckey.rsa.der_len += sizeof asn_int;
	packet->seckey.rsa.der_len += MPIBYTES(packet->seckey.rsa.modulus_n->length) + 1;
	packet->seckey.rsa.der_len += sizeof asn_int;
	packet->seckey.rsa.der_len += MPIBYTES(packet->seckey.rsa.exponent_d->length);
	header.len = packet->seckey.rsa.der_len;
	header.len = BETOH16(header.raw);
	header.raw[1] -= 4;

	/* allocate the DER data octet string data */
	xcalloc(&packet->seckey.rsa.der_data, 1, packet->seckey.rsa.der_len, "der_encode() xcalloc()");

	/* header */
	memcpy(packet->seckey.rsa.der_data + der_offset, asn_seq, sizeof asn_seq);
	der_offset += sizeof asn_seq;
	memcpy(packet->seckey.rsa.der_data + der_offset, header.raw, sizeof header.raw);
	der_offset += sizeof header.raw;
	/* version */
	memcpy(packet->seckey.rsa.der_data + der_offset,
			packet->seckey.rsa.version, sizeof packet->seckey.rsa.version);
	der_offset += sizeof packet->seckey.rsa.version;

	/* modulus_n */
	memcpy(packet->seckey.rsa.der_data + der_offset, asn_int, sizeof asn_int);
	der_offset += sizeof asn_int;
	memcpy(packet->seckey.rsa.der_data + der_offset, packet->seckey.rsa.modulus_n->be_raw, 2);
	der_offset += 2;
	memcpy(packet->seckey.rsa.der_data + der_offset,
			packet->seckey.rsa.modulus_n->mdata, MPIBYTES(packet->seckey.rsa.modulus_n->length) + 1);
	der_offset += MPIBYTES(packet->seckey.rsa.modulus_n->length) + 1;

	/* exponent_d */
	memcpy(packet->seckey.rsa.der_data + der_offset, asn_int, sizeof asn_int);
	der_offset += sizeof asn_int;
	packet->seckey.rsa.exponent_d->be_raw[1]--;
	memcpy(packet->seckey.rsa.der_data + der_offset, packet->seckey.rsa.exponent_d->be_raw, 2);
	der_offset += 2;
	memcpy(packet->seckey.rsa.der_data + der_offset,
			packet->seckey.rsa.exponent_d->mdata + 1, MPIBYTES(packet->seckey.rsa.exponent_d->length));
	der_offset += MPIBYTES(packet->seckey.rsa.exponent_d->length);

	assert(packet->seckey.rsa.der_len == der_offset);

	return der_offset;
}

size_t der_encode_alt(PGP_PACKET *restrict packet)
{
	/* SEQUENCE, TWO LENGTH BYTES */
	u8 asn_seq[2] = {0x30, 0x82};
	u8 asn_int[2] = {0x02, 0x82};
	u8 asn_small_int[2] = {0x02, 0x03};
	union { u8 raw[2]; u16 len; } header;
	/* version header bytes `0x02, 0x01, 0x00` for INTEGER, SIZE 1, DATA */
	packet->seckey.rsa.version[0] = 0x02;
	packet->seckey.rsa.version[1] = 0x01;
	packet->seckey.rsa.version[2] = 0x00;
	size_t der_offset = 0;

	/* get total length */

	packet->seckey.rsa.der_len = 0;
	packet->seckey.rsa.der_len += sizeof asn_seq;
	packet->seckey.rsa.der_len += sizeof header.raw;
	packet->seckey.rsa.der_len += sizeof packet->seckey.rsa.version;
	/* add space for MPI length bytes */
	packet->seckey.rsa.der_len += DER_TOTAL_LEN_ALT;
	packet->seckey.rsa.der_len += sizeof asn_int;
	packet->seckey.rsa.der_len += MPIBYTES(packet->seckey.rsa.modulus_n->length) + 1;
	packet->seckey.rsa.der_len += sizeof asn_small_int;
	packet->seckey.rsa.der_len += MPIBYTES(packet->seckey.rsa.exponent_e->length);
	packet->seckey.rsa.der_len += sizeof asn_int;
	packet->seckey.rsa.der_len += MPIBYTES(packet->seckey.rsa.exponent_d->length);
	packet->seckey.rsa.der_len += sizeof asn_int;
	packet->seckey.rsa.der_len += MPIBYTES(packet->seckey.rsa.prime_p->length);
	packet->seckey.rsa.der_len += sizeof asn_int;
	packet->seckey.rsa.der_len += MPIBYTES(packet->seckey.rsa.prime_q->length);
	/*
	 * TODO: implement dP and dQ calculation
	 *
	 */
	/* packet->seckey.rsa.der_len += sizeof asn_int; */
	/* packet->seckey.rsa.der_len += MPIBYTES(packet->seckey.rsa.exponent_dP->length); */
	/* packet->seckey.rsa.der_len += sizeof asn_int; */
	/* packet->seckey.rsa.der_len += MPIBYTES(packet->seckey.rsa.exponent_dQ->length); */
	packet->seckey.rsa.der_len += sizeof asn_int;
	packet->seckey.rsa.der_len += MPIBYTES(packet->seckey.rsa.mult_inverse->length);
	header.len = packet->seckey.rsa.der_len;
	header.len = BETOH16(header.raw);
	header.raw[1] -= 4;

	/* allocate the DER data octet string data */
	xcalloc(&packet->seckey.rsa.der_data, 1, packet->seckey.rsa.der_len, "der_encode() xcalloc()");

	/* header */
	memcpy(packet->seckey.rsa.der_data + der_offset, asn_seq, sizeof asn_seq);
	der_offset += sizeof asn_seq;
	memcpy(packet->seckey.rsa.der_data + der_offset, header.raw, sizeof header.raw);
	der_offset += sizeof header.raw;
	/* version */
	memcpy(packet->seckey.rsa.der_data + der_offset,
			packet->seckey.rsa.version, sizeof packet->seckey.rsa.version);
	der_offset += sizeof packet->seckey.rsa.version;

	/* modulus_n */
	memcpy(packet->seckey.rsa.der_data + der_offset, asn_int, sizeof asn_int);
	der_offset += sizeof asn_int;
	memcpy(packet->seckey.rsa.der_data + der_offset, packet->seckey.rsa.modulus_n->be_raw, 2);
	der_offset += 2;
	memcpy(packet->seckey.rsa.der_data + der_offset,
			packet->seckey.rsa.modulus_n->mdata, MPIBYTES(packet->seckey.rsa.modulus_n->length) + 1);
	der_offset += MPIBYTES(packet->seckey.rsa.modulus_n->length) + 1;

	/* exponent_e */
	memcpy(packet->seckey.rsa.der_data + der_offset, asn_small_int, sizeof asn_small_int);
	der_offset += sizeof asn_small_int;
	/* memcpy(packet->seckey.rsa.der_data + der_offset, packet->seckey.rsa.exponent_e->be_raw, 1); */
	/* der_offset += 1; */
	memcpy(packet->seckey.rsa.der_data + der_offset,
			packet->seckey.rsa.exponent_e->mdata + 1, MPIBYTES(packet->seckey.rsa.exponent_e->length));
	der_offset += MPIBYTES(packet->seckey.rsa.exponent_e->length);
	/* exponent_d */
	memcpy(packet->seckey.rsa.der_data + der_offset, asn_int, sizeof asn_int);
	der_offset += sizeof asn_int;
	packet->seckey.rsa.exponent_d->be_raw[1]--;
	memcpy(packet->seckey.rsa.der_data + der_offset, packet->seckey.rsa.exponent_d->be_raw, 2);
	der_offset += 2;
	memcpy(packet->seckey.rsa.der_data + der_offset,
			packet->seckey.rsa.exponent_d->mdata + 1, MPIBYTES(packet->seckey.rsa.exponent_d->length));
	der_offset += MPIBYTES(packet->seckey.rsa.exponent_d->length);

	/* prime_p */
	memcpy(packet->seckey.rsa.der_data + der_offset, asn_int, sizeof asn_int);
	der_offset += sizeof asn_int;
	packet->seckey.rsa.prime_p->be_raw[1]--;
	memcpy(packet->seckey.rsa.der_data + der_offset, packet->seckey.rsa.prime_p->be_raw, 2);
	der_offset += 2;
	memcpy(packet->seckey.rsa.der_data + der_offset,
			packet->seckey.rsa.prime_p->mdata, MPIBYTES(packet->seckey.rsa.prime_p->length));
	der_offset += MPIBYTES(packet->seckey.rsa.prime_p->length);
	/* prime_q */
	memcpy(packet->seckey.rsa.der_data + der_offset, asn_int, sizeof asn_int);
	der_offset += sizeof asn_int;
	packet->seckey.rsa.prime_q->be_raw[1]--;
	memcpy(packet->seckey.rsa.der_data + der_offset, packet->seckey.rsa.prime_q->be_raw, 2);
	der_offset += 2;
	memcpy(packet->seckey.rsa.der_data + der_offset,
			packet->seckey.rsa.prime_q->mdata, MPIBYTES(packet->seckey.rsa.prime_q->length));
	der_offset += MPIBYTES(packet->seckey.rsa.prime_q->length);

	/*
	 * TODO: implement dP and dQ calculation
	 */
	/* exponent_dP */
	/*
	 * memcpy(packet->seckey.rsa.der_data + der_offset, asn_int, sizeof asn_int);
	 * der_offset += sizeof asn_int;
	 * memcpy(packet->seckey.rsa.der_data + der_offset, HTOBE16(packet->seckey.rsa.exponent_dP->length), 2);
	 * der_offset += 2;
	 * memcpy(packet->seckey.rsa.der_data + der_offset,
	 *                 packet->seckey.exponent_dP.mdata, MPIBYTES(packet->seckey.rsa.exponent_dP->length));
	 * der_offset += MPIBYTES(packet->seckey.rsa.exponent_dP->length);
	 */
	/* exponent_dQ */
	/*
	 * memcpy(packet->seckey.rsa.der_data + der_offset, asn_int, sizeof asn_int);
	 * der_offset += sizeof asn_int;
	 * memcpy(packet->seckey.rsa.der_data + der_offset, HTOBE16(packet->seckey.rsa.exponent_dQ->length), 2);
	 * der_offset += 2;
	 * memcpy(packet->seckey.rsa.der_data + der_offset,
	 *                 packet->seckey.exponent_dQ.mdata, MPIBYTES(packet->seckey.rsa.exponent_dQ->length));
	 * der_offset += MPIBYTES(packet->seckey.rsa.exponent_dQ->length);
	 */

	/* mult_inverse */
	memcpy(packet->seckey.rsa.der_data + der_offset, asn_int, sizeof asn_int);
	der_offset += sizeof asn_int;
	packet->seckey.rsa.mult_inverse->be_raw[1]--;
	memcpy(packet->seckey.rsa.der_data + der_offset, packet->seckey.rsa.mult_inverse->be_raw, 2);
	der_offset += 2;
	memcpy(packet->seckey.rsa.der_data + der_offset,
			packet->seckey.rsa.mult_inverse->mdata, MPIBYTES(packet->seckey.rsa.mult_inverse->length));
	der_offset += MPIBYTES(packet->seckey.rsa.mult_inverse->length);

	assert(packet->seckey.rsa.der_len == der_offset);

	return der_offset;
}
