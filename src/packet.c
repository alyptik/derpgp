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

#define ADD_TO_MPI_OFFSET(value) \
			(mpi_offset += value)
	/* one byte */
	packet->pubkey.version = packet->pdata[mpi_offset];
	assert(packet->pubkey.version == 4);
	ADD_TO_MPI_OFFSET(1);
	/* four bytes */
	packet->pubkey.timestamp = BETOH32(packet->pdata + mpi_offset);
	ADD_TO_MPI_OFFSET(4);
	/* one byte */
	packet->pubkey.algorithm = packet->pdata[mpi_offset];
	assert(packet->pubkey.algorithm == PUB_RSA);
	ADD_TO_MPI_OFFSET(1);
	/* one mpi struct */
	ADD_TO_MPI_OFFSET(read_mpi(packet->pdata + mpi_offset, &packet->pubkey.modulus_n));
	/* one mpi struct */
	ADD_TO_MPI_OFFSET(read_mpi(packet->pdata + mpi_offset, &packet->pubkey.exponent_e));
#undef ADD_TO_MPI_OFFSET

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

#ifdef _DEBUG
	/* debug printing */
	HPRINT(packet->seckey.string_to_key);
#endif

	/* string-to-key usage convention */
	switch (packet->seckey.string_to_key) {
	/* unencrypted */
	case STR_RAW:
#ifdef _DEBUG
		printf(YELLOW "%s " RST, s2k_types[packet->seckey.string_to_key]);
#endif

		/* one mpi struct */
		mpi_offset += read_mpi(packet->pdata + mpi_offset, &packet->seckey.exponent_d);
		packet->seckey.rsa.exponent_d = &packet->seckey.exponent_d;
#ifdef _DEBUG
		printf(RED "[MPI length: %#4x] " RST, packet->seckey.exponent_d.length);
#endif

		/* one mpi struct */
		mpi_offset += read_mpi(packet->pdata + mpi_offset, &packet->seckey.prime_p);
		packet->seckey.rsa.prime_p = &packet->seckey.prime_p;
#ifdef _DEBUG
		printf(RED "[MPI length: %#4x] " RST, packet->seckey.prime_p.length);
#endif

		/* one mpi struct */
		mpi_offset += read_mpi(packet->pdata + mpi_offset, &packet->seckey.prime_q);
		packet->seckey.rsa.prime_q = &packet->seckey.prime_q;
#ifdef _DEBUG
		printf(RED "[MPI length: %#4x] " RST, packet->seckey.prime_q.length);
#endif

		/* one mpi struct */
		mpi_offset += read_mpi(packet->pdata + mpi_offset, &packet->seckey.mult_inverse);
		packet->seckey.rsa.mult_inverse = &packet->seckey.mult_inverse;
#ifdef _DEBUG
		printf(RED "[MPI length: %#4x]\n" RST, packet->seckey.mult_inverse.length);
#endif

		/* encode the DER representation */
		der_encode_alt(packet);
		break;

	/* s2k specifier */
	case STR_S2K1: /* fallthrough */
	case STR_S2K2:
		/* one byte */
		packet->seckey.sym_encryption_algo = packet->pdata[mpi_offset];
		mpi_offset++;
		/* TODO XXX: implement rest of s2k handling */
#ifdef _DEBUG
		printf(YELLOW "%s\n" RST, s2k_types[packet->seckey.string_to_key]);
#endif
		break;

	/* symmetric-key algorithm */
	default:
		/* TODO XXX: implement symmetric-key handling */
#ifdef _DEBUG
		printf(YELLOW "%s\n" RST, symkey_types[packet->seckey.string_to_key]);
#endif
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

#define ADD_SIZE_TO_DER_LEN(value) \
		(packet->seckey.rsa.der_len += (value))
	packet->seckey.rsa.der_len = 0;
	ADD_SIZE_TO_DER_LEN(sizeof asn_seq);
	ADD_SIZE_TO_DER_LEN(sizeof header.raw);
	ADD_SIZE_TO_DER_LEN(sizeof packet->seckey.rsa.version);
	/* add space for MPI length bytes */
	ADD_SIZE_TO_DER_LEN(DER_TOTAL_LEN);
	ADD_SIZE_TO_DER_LEN(sizeof asn_int);
	ADD_SIZE_TO_DER_LEN(MPIBYTES(packet->seckey.rsa.modulus_n->length) + 1);
	ADD_SIZE_TO_DER_LEN(sizeof asn_int);
	ADD_SIZE_TO_DER_LEN(MPIBYTES(packet->seckey.rsa.exponent_d->length));
	header.len = packet->seckey.rsa.der_len;
	header.len = BETOH16(header.raw);
	header.raw[1] -= 4;
#undef ADD_SIZE_TO_DER_LEN

#define COPY_TO_DER(value, length) \
		do { \
			memcpy(packet->seckey.rsa.der_data + der_offset, (value), (length)); \
			der_offset += (length); \
		} while (0)
	xcalloc(&packet->seckey.rsa.der_data, 1, packet->seckey.rsa.der_len, "der_encode() xcalloc()");
	/* header */
	COPY_TO_DER(asn_seq, sizeof asn_seq);
	COPY_TO_DER(header.raw, sizeof header.raw);
	/* version */
	COPY_TO_DER(packet->seckey.rsa.version, sizeof packet->seckey.rsa.version);
	/* modulus_n */
	COPY_TO_DER(asn_int, sizeof asn_int);
	COPY_TO_DER(packet->seckey.rsa.modulus_n->be_raw, 2);
	COPY_TO_DER(packet->seckey.rsa.modulus_n->mdata, MPIBYTES(packet->seckey.rsa.modulus_n->length) + 1);
	/* exponent_d */
	COPY_TO_DER(asn_int, sizeof asn_int);
	packet->seckey.rsa.exponent_d->be_raw[1]--;
	COPY_TO_DER(packet->seckey.rsa.exponent_d->be_raw, 2);
	COPY_TO_DER(packet->seckey.rsa.exponent_d->mdata + 1, MPIBYTES(packet->seckey.rsa.exponent_d->length));
#undef COPY_TO_DER

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

#define ADD_SIZE_TO_DER_LEN(value) \
		(packet->seckey.rsa.der_len += (value))
	packet->seckey.rsa.der_len = 0;
	ADD_SIZE_TO_DER_LEN(sizeof asn_seq);
	ADD_SIZE_TO_DER_LEN(sizeof header.raw);
	ADD_SIZE_TO_DER_LEN(sizeof packet->seckey.rsa.version);
	/* add space for MPI length bytes */
	ADD_SIZE_TO_DER_LEN(DER_TOTAL_LEN_ALT);
	ADD_SIZE_TO_DER_LEN(sizeof asn_int);
	ADD_SIZE_TO_DER_LEN(MPIBYTES(packet->seckey.rsa.modulus_n->length) + 1);
	ADD_SIZE_TO_DER_LEN(sizeof asn_small_int);
	ADD_SIZE_TO_DER_LEN(MPIBYTES(packet->seckey.rsa.exponent_e->length));
	ADD_SIZE_TO_DER_LEN(sizeof asn_int);
	ADD_SIZE_TO_DER_LEN(MPIBYTES(packet->seckey.rsa.exponent_d->length));
	ADD_SIZE_TO_DER_LEN(sizeof asn_int);
	ADD_SIZE_TO_DER_LEN(MPIBYTES(packet->seckey.rsa.prime_p->length));
	ADD_SIZE_TO_DER_LEN(sizeof asn_int);
	ADD_SIZE_TO_DER_LEN(MPIBYTES(packet->seckey.rsa.prime_q->length));
	/*
	 * TODO: implement dP and dQ calculation
	 *
	 * ADD_DER_LEN(sizeof asn_int);
	 * ADD_DER_LEN(MPIBYTES(packet->seckey.rsa.exponent_dP->length));
	 * ADD_DER_LEN(sizeof asn_int);
	 * ADD_DER_LEN(MPIBYTES(packet->seckey.rsa.exponent_dQ->length));
	 */
	ADD_SIZE_TO_DER_LEN(sizeof asn_int);
	ADD_SIZE_TO_DER_LEN(MPIBYTES(packet->seckey.rsa.mult_inverse->length));
	header.len = packet->seckey.rsa.der_len;
	header.len = BETOH16(header.raw);
	header.raw[1] -= 4;
#undef ADD_SIZE_TO_DER_LEN

#define COPY_TO_DER(value, length) \
		do { \
			memcpy(packet->seckey.rsa.der_data + der_offset, (value), (length)); \
			der_offset += (length); \
		} while (0)
	xcalloc(&packet->seckey.rsa.der_data, 1, packet->seckey.rsa.der_len, "der_encode_alt() xcalloc()");
	/* header */
	COPY_TO_DER(asn_seq, sizeof asn_seq);
	COPY_TO_DER(header.raw, sizeof header.raw);
	/* version */
	COPY_TO_DER(packet->seckey.rsa.version, sizeof packet->seckey.rsa.version);
	/* modulus_n */
	COPY_TO_DER(asn_int, sizeof asn_int);
	COPY_TO_DER(packet->seckey.rsa.modulus_n->be_raw, 2);
	COPY_TO_DER(packet->seckey.rsa.modulus_n->mdata, MPIBYTES(packet->seckey.rsa.modulus_n->length) + 1);
	/* exponent_e */
	COPY_TO_DER(asn_small_int, sizeof asn_small_int);
	/* COPY_TO_DER(packet->seckey.rsa.exponent_e->be_raw, 1); */
	COPY_TO_DER(packet->seckey.rsa.exponent_e->mdata + 1, MPIBYTES(packet->seckey.rsa.exponent_e->length));
	/* exponent_d */
	COPY_TO_DER(asn_int, sizeof asn_int);
	packet->seckey.rsa.exponent_d->be_raw[1]--;
	COPY_TO_DER(packet->seckey.rsa.exponent_d->be_raw, 2);
	COPY_TO_DER(packet->seckey.rsa.exponent_d->mdata + 1, MPIBYTES(packet->seckey.rsa.exponent_d->length));
	/* prime_p */
	COPY_TO_DER(asn_int, sizeof asn_int);
	packet->seckey.rsa.prime_p->be_raw[1]--;
	COPY_TO_DER(packet->seckey.rsa.prime_p->be_raw, 2);
	COPY_TO_DER(packet->seckey.rsa.prime_p->mdata, MPIBYTES(packet->seckey.rsa.prime_p->length));
	/* prime_q */
	COPY_TO_DER(asn_int, sizeof asn_int);
	packet->seckey.rsa.prime_q->be_raw[1]--;
	COPY_TO_DER(packet->seckey.rsa.prime_q->be_raw, 2);
	COPY_TO_DER(packet->seckey.rsa.prime_q->mdata, MPIBYTES(packet->seckey.rsa.prime_q->length));
	/*
	 * TODO: implement dP and dQ calculation
	 *
	 * exponent_dP
	 * COPY_TO_DER((asn_int), (sizeof asn_int));
	 * COPY_TO_DER((HTOBE16(packet->seckey.rsa.exponent_dP->length)), 2);
	 * COPY_TO_DER((packet->seckey.exponent_dP.mdata), MPIBYTES(packet->seckey.rsa.exponent_dP->length));
	 * exponent_dQ
	 * COPY_TO_DER((asn_int), (sizeof asn_int));
	 * COPY_TO_DER((HTOBE16(packet->seckey.rsa.exponent_dQ->length)), 2);
	 * COPY_TO_DER((packet->seckey.exponent_dQ.mdata), MPIBYTES(packet->seckey.rsa.exponent_dQ->length));
	 */
	/* mult_inverse */
	COPY_TO_DER(asn_int, sizeof asn_int);
	packet->seckey.rsa.mult_inverse->be_raw[1]--;
	COPY_TO_DER(packet->seckey.rsa.mult_inverse->be_raw, 2);
	COPY_TO_DER(packet->seckey.rsa.mult_inverse->mdata, MPIBYTES(packet->seckey.rsa.mult_inverse->length));
#undef COPY_TO_DER

	assert(packet->seckey.rsa.der_len == der_offset);

	return der_offset;
}
