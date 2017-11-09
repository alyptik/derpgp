/*
 * defs.h:	data structure and macro definitions
 *
 * AUTHORS:	Joey Pabalinas <alyptik@protonmail.com>
 *		Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#ifndef _DEFS_H
#define _DEFS_H 1

#include "errs.h"
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

/* global version and usage strings */

#define VERSION_STRING		"DerpGP v0.0.1"
#define USAGE_STRING		"[-hv] [-i“<in.gpg>”] [-o“<out.pem>”]\n\t" \
	"-h,--help:\t\tShow help/usage information\n\t" \
	"-i,--input:\t\tName of the file to use for input\n\t" \
	"-o,--output:\t\tName of the file to use for output\n\t" \
	"-v,--version:\t\tShow version information\n\t"
#define	RED			"\033[91m"
#define	GREEN			"\033[92m"
#define	YELLOW			"\033[93m"
#define	BLUE			"\033[94m"
#define	PURPLE			"\033[95m"
#define	RST			"\033[00m"
/* page size for buffer count */
#define PAGE_SIZE		sysconf(_SC_PAGESIZE)
/* max eval string length */
#define EVAL_LIMIT		4096
/* `strmv() `concat constant */
#define CONCAT			(-1)
/* `malloc()` size ceiling */
#define ARRAY_MAX		(SIZE_MAX / 2 - 1)

/* macros */

#define FALLBACK(ARG, DEF)	((ARG) ? (ARG) : (DEF))
#define BETOH16(DATA)		(((DATA)[1]) | ((DATA)[0] << 0x08))
#define BETOH32(DATA)		(((DATA)[3]) | ((DATA)[2] << 0x08) | ((DATA)[1] << 0x10) | ((DATA)[0] << 0x18))
#define TAGBITS(DATA)		(((DATA) & 0x3c) >> 2)
#define FMTBITS(DATA)		(((DATA) & (0x01 << 6)) >> 6)
#define HPRINT(VAL)		printf(RED "[%#x] " RST, (VAL))

/* typedefs */

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* enumerations */

/* packet header is defined as `[2 bit format][4 bit type][2 bit length size]` */
enum packet_header {
	/* packet formats */
	F_OLD = 0x00,
	F_NEW = 0x01,
};

/* packet tags */
enum packet_tag {
	/* Reserved - a packet tag MUST NOT have this value */
	T_RSRVD = 0x00,
	/* Public-Key Encrypted Session Key Packet */
	T_PKESESS = 0x01,
	/* Signature Packet */
	T_SIG = 0x02,
	/* Symmetric-Key Encrypted Session Key Packet */
	T_SKESESS = 0x03,
	/* One-Pass Signature Packet */
	T_OPSIG = 0x04,
	/* Secret-Key Packet */
	T_SECKEY = 0x05,
	/* Public-Key Packet */
	T_PUBKEY = 0x06,
	/* Secret-Subkey Packet */
	T_SECSUBKEY = 0x07,
	/* Compressed Data Packet */
	T_CDATA = 0x08,
	/* Symmetrically Encrypted Data Packet */
	T_SEDATA = 0x09,
	/* Marker Packet */
	T_MARKER = 0x0a,
	/* Literal Data Packet */
	T_LITDATA = 0x0b,
	/* Trust Packet */
	T_TRUST = 0x0c,
	/* User ID Packet */
	T_UID = 0x0d,
	/* Public-Subkey Packet */
	T_PUBSUBKEY = 0x0e,
	/* User Attribute Packet */
	T_UATTR = 0x11,
	/* Sym. Encrypted and Integrity Protected Data Packet */
	T_SEIPDATA = 0x12,
	/* Modification Detection Code Packet */
	T_MDCODE = 0x13,
	/* Private or Experimental Values */
	T_PRVT0 = 0x3c,
	T_PRVT1 = 0x3d,
	T_PRVT2 = 0x3e,
	T_PRVT3 = 0x3f,
};

/* old format packet lengths */
enum packet_lengths {
	L_ONE = 0x00,
	L_TWO = 0x01,
	L_FOUR = 0x02,
	L_OTHER = 0x03,
};
/* TODO XXX: add support for new format packet headers */

/* pubkey algorithm types */
enum pubkey_algorithms {
	/* RSA (Encrypt or Sign) [HAC] */
	PUB_RSA = 0x01,
	/* RSA Encrypt-Only [HAC] */
	PUB_RSAENC = 0x02,
	/* RSA Sign-Only [HAC] */
	PUB_RSASIG = 0x03,
	/* Elgamal (Encrypt-Only) [ELGAMAL] [HAC] */
	PUB_ELGAENC = 0x10,
	/* DSA (Digital Signature Algorithm) [FIPS186] [HAC] */
	PUB_DSA = 0x11,
	/* Reserved for Elliptic Curve */
	PUB_ELCURVE = 0x12,
	/* Reserved for ECDSA */
	PUB_ECDSA = 0x13,
	/* Reserved (formerly Elgamal Encrypt or Sign) */
	PUB_ELGA = 0x14,
	/* Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME) */
	PUB_DH = 0x15,
	/* Private/Experimental algorithm */
	PUB_PRIV0 = 0x64, PUB_PRIV1 = 0x65,
	PUB_PRIV2 = 0x66, PUB_PRIV3 = 0x67,
	PUB_PRIV4 = 0x68, PUB_PRIV5 = 0x69,
	PUB_PRIV6 = 0x6a, PUB_PRIV7 = 0x6b,
	PUB_PRIV8 = 0x6c, PUB_PRIV9 = 0x6d,
};

/* symmetric-key algorithm types */
enum symkey_algorithms {
	/* Plaintext or unencrypted data */
	SYM_RAW = 0x00,
	/* IDEA [IDEA] */
	SYM_IDEA = 0x01,
	/* TripleDES (DES-EDE, [SCHNEIER] [HAC] - 168 bit key derived from 192) */
	SYM_TDES = 0x02,
	/* CAST5 (128 bit key, as per [RFC2144]) */
	SYM_CAST4 = 0x04,
	/* Blowfish (128 bit key, 16 rounds) [BLOWFISH] */
	SYM_BLOWFISH = 0x04,
	/* Reserved */
	SYM_RSRVD0 = 0x05,
	/* Reserved */
	SYM_RSRVD1 = 0x06,
	/* AES with 128-bit key [AES] */
	SYM_AES128 = 0x07,
	/* AES with 192-bit key */
	SYM_AES192 = 0x08,
	/* AES with 256-bit key */
	SYM_AES256 = 0x09,
	/* Twofish with 256-bit key [TWOFISH] */
	SYM_TWOFISH = 0x0a,
	/* Private/Experimental algorithm */
	SYM_PRIV0 = 0x64, SYM_PRIV1 = 0x65,
	SYM_PRIV2 = 0x66, SYM_PRIV3 = 0x67,
	SYM_PRIV4 = 0x68, SYM_PRIV5 = 0x69,
	SYM_PRIV6 = 0x6a, SYM_PRIV7 = 0x6b,
	SYM_PRIV8 = 0x6c, SYM_PRIV9 = 0x6d,
};

/* string-to-key usage conventions */
enum s2k_conventions {
	T_RAW = 0x00,
	T_S2K1 = 0xfe,
	T_S2K2 = 0xff,
};

/* structures */

/* Multi precision integers */
typedef struct _MPI {
	u16 length;
	u8 *mdata;
} MPI;

/*
 * pgp packet types
 */

/* Reserved - a packet tag MUST NOT have this value */
typedef struct  _rsrvd_packet {
	u8 *octets;
} RSRVD_PACKET;

/* Public-Key Encrypted Session Key Packet */
typedef struct  _pkesess_packet {
	u8 *octets;
} PKESESS_PACKET;

/* Symmetric-Key Encrypted Session Key Packet */
typedef struct  _skesess_packet {
	u8 *octets;
} SKESESS_PACKET;

/* One-Pass Signature Packet */
typedef struct  _opsig_packet {
	u8 *octets;
} OPSIG_PACKET;

/* Secret-Key Packet */
typedef struct  _seckey_packet {
	u8 string_to_key;
	u8 sym_encryption_algo;
	u8 *iv;
	MPI exponent_d;
	MPI prime_p;
	MPI prime_q;
	MPI mult_inverse;
	u16 checksum;
} SECKEY_PACKET;

/* Public-Key Packet
 * FIXME: we only support V4 :>
 */
typedef struct  _pubkey_packet {
	/* NOTE: must be always 4 (or 3 in the future) */
	u8 version;
	/* posix timestamp */
	u32 timestamp;
	/* 1 for RSA, 2 for DSA */
	u8 algorithm;
	MPI modulus_n;
	MPI exponent;
} PUBKEY_PACKET;

/* Secret-Subkey Packet */
typedef struct  _secsubkey_packet {
	u8 *octets;
} SECSUBKEY_PACKET;

/* Compressed Data Packet */
typedef struct  _cdata_packet {
	u8 *octets;
} CDATA_PACKET;

/* Symmetrically Encrypted Data Packet */
typedef struct  _sedat_packet {
	u8 *octets;
} SEDAT_PACKET;

/* Marker Packet */
typedef struct  _marker_packet {
	u8 *octets;
} MARKER_PACKET;

/* Literal Data Packet */
typedef struct  _litdata_packet {
	u8 *octets;
} LITDATA_PACKET;

/* Trust Packet */
typedef struct  _trust_packet {
	u8 *octets;
} TRUST_PACKET;

/* User ID Packet */
typedef struct  _ui_packet {
	u8 *octets;
} UI_PACKET;

/* Public-Subkey Packet */
typedef struct  _pubsubkey_packet {
	u8 *octets;
} PUBSUBKEY_PACKET;

/* User Attribute Packet */
typedef struct  _uattr_packet {
	u8 *octets;
} UATTR_PACKET;

/* Sym. Encrypted and Integrity Protected Data Packet */
typedef struct  _seipdata_packet {
	u8 *octets;
} SEIPDATA_PACKET;

/* Modification Detection Code Packet */
typedef struct  _mdcode_packet {
	u8 *octets;
} MDCODE_PACKET;

/* Private or Experimental Values */
typedef struct  _prvt0_packet {
	u8 *octets;
} PRVT0_PACKET;
typedef struct  _prvt1_packet {
	u8 *octets;
} PRVT1_PACKET;
typedef struct  _prvt2_packet {
	u8 *octets;
} PRVT2_PACKET;
typedef struct  _prvt3_packet {
	u8 *octets;
} PRVT3_PACKET;

/* struct definition for pgp packet data */
typedef struct _pgp_packet {
	u8 pheader;
	union {
		u8 plen_one;
		u16 plen_two;
		u32 plen_four;
	};
	u8 plen_raw[4];
	u8 *pdata;
	/* parsed packet data */
	union {
		RSRVD_PACKET rsrvd;
		PKESESS_PACKET pkesess;
		SKESESS_PACKET skesess;
		OPSIG_PACKET opsig;
		SECKEY_PACKET seckey;
		PUBKEY_PACKET pubkey;
		SECSUBKEY_PACKET secsubkey;
		CDATA_PACKET cdata;
		SEDAT_PACKET sedat;
		MARKER_PACKET marker;
		LITDATA_PACKET litdata;
		TRUST_PACKET trust;
		UI_PACKET ui;
		PUBSUBKEY_PACKET pubsubkey;
		UATTR_PACKET uattr;
		SEIPDATA_PACKET seipdata;
		MDCODE_PACKET mdcode;
		PRVT0_PACKET prvt0;
		PRVT1_PACKET prvt1;
		PRVT2_PACKET prvt2;
		PRVT3_PACKET prvt3;
	};
} PGP_PACKET;

/* struct definition for dynamic array of pgp structs */
typedef struct _pgp_list {
	size_t cnt, max;
	PGP_PACKET *list;
} PGP_LIST;

/* struct definition for NULL-terminated string dynamic array */
typedef struct _str_list {
	size_t cnt, max;
	char **list;
} STR_LIST;

/* packet tag names for debug printing */
static char const *const packet_types[64] = {
	[T_RSRVD] = "T_RSRVD", [T_PKESESS] = "T_PKESESS",
	[T_SIG] = "T_SIG", [T_SKESESS] = "T_SKESESS",
	[T_OPSIG] = "T_OPSIG", [T_SECKEY] = "T_SECKEY",
	[T_PUBKEY] = "T_PUBKEY", [T_SECSUBKEY] = "T_SECSUBKEY",
	[T_CDATA] = "T_CDATA", [T_SEDATA] = "T_SEDATA",
	[T_MARKER] = "T_MARKER", [T_LITDATA] = "T_LITDATA",
	[T_TRUST] = "T_TRUST", [T_UID] = "T_UID",
	[T_PUBSUBKEY] = "T_PUBSUBKEY", [T_UATTR] = "T_UATTR",
	[T_SEIPDATA] = "T_SEIPDATA", [T_MDCODE] = "T_MDCODE",
	[T_PRVT0] = "T_PRVT0", [T_PRVT1] = "T_PRVT1",
	[T_PRVT2] = "T_PRVT2", [T_PRVT3] = "T_PRVT3",
};

/* `malloc()` wrapper */
static inline void xmalloc(void *restrict ptr, size_t sz, char const *msg)
{
	/* sanity check */
	if (!ptr)
		return;
	if (!(*(void **)ptr = malloc(sz)))
		ERR(msg ? msg : "(nil)");
}

/* `calloc()` wrapper */
static inline void xcalloc(void *restrict ptr, size_t nmemb, size_t sz, char const *msg)
{
	/* sanity check */
	if (!ptr)
		return;
	if (!(*(void **)ptr = calloc(nmemb, sz)))
		ERR(msg ? msg : "(nil)");
}

/* `realloc()` wrapper */
static inline void xrealloc(void *restrict ptr, size_t sz, char const *msg)
{
	void *tmp;
	/* sanity check */
	if (!ptr)
		return;
	if (!(tmp = realloc(*(void **)ptr, sz)))
		ERR(msg ? msg : "(nil)");
	*(void **)ptr = tmp;
}

/* `fclose()` wrapper */
static inline void xfclose(FILE **restrict out_file)
{
	if (!out_file || !*out_file)
		return;
	if (!fclose(*out_file))
		WARN("xfclose()");
}

/* `fopen()` wrapper */
static inline FILE *xfopen(char const *restrict path, char const *restrict fmode)
{
	FILE *file;
	if (!(file = fopen(path, fmode)))
		ERR("xfopen()");
	return file;
}

/* `fread()` wrapper */
static inline size_t xfread(void *restrict ptr, size_t sz, size_t nmemb, FILE *restrict stream)
{
	size_t cnt;
	if ((cnt = fread(ptr, sz, nmemb, stream)) < nmemb)
		return 0;
	return cnt;
}

/* recursive free */
static inline ptrdiff_t free_argv(char ***restrict argv)
{
	ptrdiff_t cnt;
	if (!argv || !*argv)
		return -1;
	for (cnt = 0; (*argv)[cnt]; cnt++)
		free((*argv)[cnt]);
	free(*argv);
	*argv = NULL;
	return cnt;
}

/* emulate `strcat()` if `off < 0`, else copy `src` to `dest` at offset `off` */
static inline void strmv(ptrdiff_t off, char *restrict dest, char const *restrict src)
{
	/* sanity checks */
	if (!dest || !src)
		ERRX("NULL pointer passed to strmv()");
	ptrdiff_t src_sz;
	char *dest_ptr = NULL, *src_ptr = memchr(src, '\0', EVAL_LIMIT);
	if (off >= 0) {
		dest_ptr = dest + off;
	} else {
		dest_ptr = memchr(dest, '\0', EVAL_LIMIT);
	}
	if (!src_ptr || !dest_ptr)
		ERRX("strmv() string not null-terminated");
	src_sz = src_ptr - src;
	memcpy(dest_ptr, src, (size_t)src_sz + 1);
}

static inline ptrdiff_t free_str_list(STR_LIST *restrict plist)
{
	size_t null_cnt = 0;
	/* return -1 if passed NULL pointers */
	if (!plist || !plist->list)
		return -1;
	for (size_t i = 0; i < plist->cnt; i++) {
		/* if NULL increment counter and skip */
		if (!plist->list[i]) {
			null_cnt++;
			continue;
		}
		free(plist->list[i]);
		plist->list[i] = NULL;
	}
	free(plist->list);
	plist->list = NULL;
	plist->cnt = 0;
	plist->max = 1;
	return null_cnt;
}

static inline void init_str_list(STR_LIST *restrict list_struct, char *restrict init_str)
{
	list_struct->cnt = 0;
	list_struct->max = 1;
	if (!(list_struct->list = calloc(1, sizeof *list_struct->list)))
		ERR("error during initial list_ptr calloc()");
	/* exit early if NULL */
	if (!init_str)
		return;
	list_struct->cnt++;
	if (!(list_struct->list[list_struct->cnt - 1] = calloc(1, strlen(init_str) + 1)))
		ERR("error during initial list_ptr[0] calloc()");
	memcpy(list_struct->list[list_struct->cnt - 1], init_str, strlen(init_str) + 1);
}

static inline void append_str(STR_LIST *restrict list_struct, char const *restrict string, size_t pad)
{
	void *tmp;
	list_struct->cnt++;
	/* realloc if cnt reaches current size */
	if (list_struct->cnt >= list_struct->max) {
		/* check if size too large */
		if (list_struct->cnt > ARRAY_MAX)
			ERRX("list_struct->cnt > (SIZE_MAX / 2 - 1)");
		list_struct->max *= 2;
		if (!(tmp = realloc(list_struct->list, sizeof *list_struct->list * list_struct->max)))
			ERRARR("list_ptr", list_struct->cnt - 1);
		list_struct->list = tmp;
	}
	if (!string) {
		list_struct->list[list_struct->cnt - 1] = NULL;
		return;
	}
	if (!(list_struct->list[list_struct->cnt - 1] = calloc(1, strlen(string) + pad + 1)))
		ERRARR("list_ptr", list_struct->cnt - 1);
	memcpy(list_struct->list[list_struct->cnt - 1] + pad, string, strlen(string) + 1);
}

#endif
