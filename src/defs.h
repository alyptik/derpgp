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
/*
 * Subtypes for the ring trust gpg packets.
 */
/* The classical signature cache. */
#define RING_TRUST_SIG 0
/* A KEYORG on a primary key. */
#define RING_TRUST_KEY 1
/* A KEYORG on a user id. */
#define RING_TRUST_UID 2
/* total MPI length bytes */
#define DER_TOTAL_LEN 4
#define DER_TOTAL_LEN_ALT 10
/* including dP and dQ */
/* #define DER_TOTAL_LEN_ALT 14 */

/* macros */

#define FALLBACK(ARG, DEF)	((ARG) ? (ARG) : (DEF))
#define BETOH16(DATA)		(((DATA)[1]) | ((DATA)[0] << 0x08))
#define HTOBE16(DATA)		(((DATA)[0]) | ((DATA)[1] << 0x08))
#define BETOH32(DATA)		(((DATA)[3]) | ((DATA)[2] << 0x08) | ((DATA)[1] << 0x10) | ((DATA)[0] << 0x18))
#define HTOBE32(DATA)		(((DATA)[0]) | ((DATA)[1] << 0x08) | ((DATA)[2] << 0x10) | ((DATA)[3] << 0x18))
#define TOBYTES(DATA)		((uint8_t *)&DATA)
#define TAGBITS(DATA)		(((DATA) & 0x3c) >> 2)
#define FMTBITS(DATA)		(((DATA) & (0x01 << 6)) >> 6)
#define HPRINT(VAL)		printf(RED "[%#x] " RST, (VAL))
#define MPIBYTES(BITLEN)	(((BITLEN) + 7) / 8)

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
enum header_format {
	/* packet formats */
	FMT_OLD = 0x00,
	FMT_NEW = 0x01,
};

/* packet tags */
enum packet_tag {
	/* Reserved - a packet tag MUST NOT have this value */
	TAG_RSRVD = 0x00,
	/* Public-Key Encrypted Session Key Packet */
	TAG_PKESESS = 0x01,
	/* Signature Packet */
	TAG_SIG = 0x02,
	/* Symmetric-Key Encrypted Session Key Packet */
	TAG_SKESESS = 0x03,
	/* One-Pass Signature Packet */
	TAG_OPSIG = 0x04,
	/* Secret-Key Packet */
	TAG_SECKEY = 0x05,
	/* Public-Key Packet */
	TAG_PUBKEY = 0x06,
	/* Secret-Subkey Packet */
	TAG_SECSUBKEY = 0x07,
	/* Compressed Data Packet */
	TAG_CDATA = 0x08,
	/* Symmetrically Encrypted Data Packet */
	TAG_SEDATA = 0x09,
	/* Marker Packet */
	TAG_MARKER = 0x0a,
	/* Literal Data Packet */
	TAG_LITDATA = 0x0b,
	/* Trust Packet */
	TAG_TRUST = 0x0c,
	/* User ID Packet */
	TAG_UID = 0x0d,
	/* Public-Subkey Packet */
	TAG_PUBSUBKEY = 0x0e,
	/* User Attribute Packet */
	TAG_UATTR = 0x11,
	/* Sym. Encrypted and Integrity Protected Data Packet */
	TAG_SEIPDATA = 0x12,
	/* Modification Detection Code Packet */
	TAG_MDCODE = 0x13,
	/* Private or Experimental Values */
	TAG_PRVT0 = 0x3c,
	TAG_PRVT1 = 0x3d,
	TAG_PRVT2 = 0x3e,
	TAG_PRVT3 = 0x3f,
};

/* old format packet lengths */
enum packet_lengths {
	LEN_ONE = 0x00,
	LEN_TWO = 0x01,
	LEN_FOUR = 0x02,
	LEN_OTHER = 0x03,
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
	SYM_CAST5 = 0x03,
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

/* compression algorithms */
enum compression_algorithms {
	/* Uncompressed */
	CMPR_RAW = 0x00,
	/* ZIP [RFC1951] */
	CMPR_ZIP = 0x01,
	/* ZLIB [RFC1950] */
	CMPR_ZLIB = 0x02,
	/* BZip2 [BZ2] */
	CMPR_BZ2 = 0x03,
	/* Private/Experimental algorithm */
	CMPR_PRIV0 = 0x64, CMPR_PRIV1 = 0x65,
	CMPR_PRIV2 = 0x66, CMPR_PRIV3 = 0x67,
	CMPR_PRIV4 = 0x68, CMPR_PRIV5 = 0x69,
	CMPR_PRIV6 = 0x6a, CMPR_PRIV7 = 0x6b,
	CMPR_PRIV8 = 0x6c, CMPR_PRIV9 = 0x6d,
};

/* string-to-key usage conventions */
enum s2k_conventions {
	/* unencrypted */
	STR_RAW = 0x00,
	/* followed by algorithm octet and S2K specifier */
	STR_S2K1 = 0xfe, STR_S2K2 = 0xff,
};

/* hash algorithms */
enum hash_algorithms {
	/* MD5 [HAC] "MD5" */
	HASH_MD5 = 0x01,
	/* SHA-1 [FIPS180] "SHA1" */
	HASH_SHA1 = 0x02,
	/* RIPE-MD/160 [HAC] "RIPEMD160" */
	HASH_RIPE = 0x03,
	/* Reserved */
	HASH_RSVRD0 = 0x04, HASH_RSVRD1 = 0x05,
	HASH_RSVRD3 = 0x06, HASH_RSVRD4 = 0x07,
	/* SHA256 [FIPS180] "SHA256" */
	HASH_SHA256 = 0x08,
	/* SHA384 [FIPS180] "SHA384" */
	HASH_SHA384 = 0x09,
	/* SHA512 [FIPS180] "SHA512" */
	HASH_SHA512 = 0x0a,
	/* SHA224 [FIPS180] "SHA224" */
	HASH_SHA224 = 0x0b,
	/* Private/Experimental algorithm */
	HASH_PRIV0 = 0x64, HASH_PRIV1 = 0x65,
	HASH_PRIV2 = 0x66, HASH_PRIV3 = 0x67,
	HASH_PRIV4 = 0x68, HASH_PRIV5 = 0x69,
	HASH_PRIV6 = 0x6a, HASH_PRIV7 = 0x6b,
	HASH_PRIV8 = 0x6c, HASH_PRIV9 = 0x6d,
};

/* structures */

/* Multi Precision Integers */
typedef struct _mpi {
	union {
		u8 be_raw[2];
		u16 be_len;
	};
	union {
		u8 len_raw[2];
		u16 length;
	};
	u8 *mdata;
} MPI;

/* String-to-Key Specifiers */
typedef struct _s2k {
	int s2k_mode;
	u8 hash_algo;
	u8 salt[8];
	/* the serialized iteration count. */
	u32 cnt;
} S2K;

/*
 * Distinguished Encoding Rules (DER) Encoded RSA Key
 *
 */
typedef struct _rsa {
	/* version header bytes `0x02, 0x01, 0x00` for INTEGER, SIZE 1, DATA */
	u8 version[3];
	MPI *modulus_n;
	MPI *exponent_e;
	MPI *exponent_d;
	MPI *prime_p;
	MPI *prime_q;
	MPI *exponent_dP;
	MPI *exponent_dQ;
	MPI *mult_inverse;
	u16 der_len;
	u8 *der_data;
} RSA;

/* Secret-Key Info */
typedef struct _seckey_info {
	/*
	 * The secret info is protected and must
	 * be decrypted before use; the protected
	 * MPIs are simply (void* ) pointers to memory
	 */
	int is_protected : 1;
	/* SHA1 instead of a 16-bit checksum */
	int sha1_chk;
	/* checksum for old protection modes */
	u16 ckh_sum;
	/* cipher used to protect the secret information */
	u8 seckey_algo;
	/* S2K parameter */
	S2K s2k;
	/* used length of the initialization vector */
	u8 iv_len;
	/* initialization vector for CFB modes */
	u8 iv[16];
} SECKEY_INFO;

/* PGP signatures have hashed and unhashed areas with signature subpackets */
typedef struct _sub_packet {
	/* allocated */
	size_t subpkt_size;
	/* used (serialized) */
	size_t subpkt_len;
	/* the serialized subpackes (serialized) */
	u8 *subpkt_data;
} SIGSUB_PACKET;

/*
 * PGP Packet Types
 */

/* Reserved - a packet tag MUST NOT have this value */
typedef struct _rsrvd_packet {
	u8 const *rsrvd_data;
} RSRVD_PACKET;

/* Public-Key Encrypted Session Key Packet */
typedef struct _pkesess_packet {
	u32 keyid[2];
	u8 version;
	u8 pub_encryption_algo;
	u8 hide_keyid;
	MPI sess_data[2];
} PKESESS_PACKET;

/* Symmetric-Key Encrypted Session Key Packet */
typedef struct _skesess_packet {
	u8 version;
	u8 cipher_algo;
	S2K s2k;
	u8 sess_len;
	u8 *sess_key;
} SKESESS_PACKET;

/* One-Pass Signature Packet */
typedef struct _opsig_packet {
	u32 keyid[2];
	u8 sig_class;
	u8 digest_algo;
	u8 pubkey_algo;
	/* if set then sign all of the data starting at the next packet */
	u8 sign_next;
} OPSIG_PACKET;

/* Secret-Key Packet */
typedef struct _seckey_packet {
	/* NOTE: must be always 4 (or 3 in the future) */
	u8 version;
	/* posix timestamp */
	u32 timestamp;
	/* 1 for RSA, 2 for DSA */
	u8 algorithm;
	MPI modulus_n;
	MPI exponent_e;
	u8 string_to_key;
	u8 sym_encryption_algo;
	u8 *iv;
	MPI exponent_d;
	MPI prime_p;
	MPI prime_q;
	MPI mult_inverse;
	u16 checksum;
	SECKEY_INFO *seckey_info;
	RSA rsa;
} SECKEY_PACKET;

/* Public-Key Packet
 *
 * FIXME: we only support V4 :>
 */
typedef struct _pubkey_packet {
	/* NOTE: must be always 4 (or 3 in the future) */
	u8 version;
	/* posix timestamp */
	u32 timestamp;
	/* 1 for RSA, 2 for DSA */
	u8 algorithm;
	MPI modulus_n;
	MPI exponent_e;
	SECKEY_INFO *seckey_info;
} PUBKEY_PACKET;

/* Secret-Subkey Packet */
typedef struct _seckey_packet SECSUBKEY_PACKET;

/* Compressed Data Packet */
typedef struct _cdata_packet {
	u32 len;
	/* whether new format is used */
	u8 new_ctb;
	u8 compr_algo;
	/* data to be decompressed */
	u8 *compr_data;
} CDATA_PACKET;

/* Symmetrically Encrypted Data Packet */
typedef struct _sedat_packet {
	/* remaining length of encrypted data */
	u32 len;
	/*
	 * the first block size bytes of data are random data
	 * and the following two bytes are copies of the last two bytes
	 * of random data.
	 */
	int extra_len;
	/* whether new format is used */
	u8 new_ctb;
	/* indeterminate length (old) or partial body length headers (new) */
	u8 is_partial;
	/*
	 * 0 is disabled; otherwise the MDC method used
	 * currently only HASH_SHA1 is supported by GnuPG
	 */
	u8 mdc_method;
	/* data to be decrypted */
	u8 *seipdata;
} SEDAT_PACKET;

/* Marker Packet (MUST BE IGNORED WHEN RECEIVED) */
typedef struct _marker_packet {
	/* the three octets 0x50, 0x47, 0x50 (which spell "PGP" in UTF-8). */
	u8 octets[3];
} MARKER_PACKET;

/* Literal Data Packet */
typedef struct _litdata_packet {
	/* length of buffer; 0 if unknown */
	u32 len;
	u8 *data_buf;
	/* whether new format is used */
	u8 new_ctb;
	/* indeterminate length (old) or partial body length headers (new) */
	u8 is_partial;
	/* data formatting: ['b', 't', 'u', 'l' or '1'] (last two are deprecated) */
	int data_mode;
	u32 timestamp;
	/* filename; at most 255 characters (max one byte when serialized) */
	int name_len;
	char *txt_name;
} LITDATA_PACKET;

/*
 * Trust Packet
 *
 * The local only ring trust packet which OpenPGP declares as
 * implementation defined. GnuPG uses this to cache signature
 * verification status and since 2.1.18 also to convey information
 * about the origin of a key. Note that this packet is not part
 * struct packet_struct because we use it only local in the packet
 * parser and builder. (from GnuPG source)
 */
typedef struct _trust_packet {
	unsigned trust_val;
	unsigned sig_cache;
	/* The subtype of this ring trust packet. */
	unsigned char sub_type;
	/* The origin of the key (KEYORG_*). */
	unsigned char key_org;
	/* The wall time the key was last updated. */
	u32 key_update;
	/* NULL or the URL of the source. */
	char *src_url;
} TRUST_PACKET;

/* forward-declaration for User ID Packet */
struct _uattr_packet;

/* User ID Packet */
typedef struct _ui_packet {
	/* reference count */
	int ref;
	int name_len;
	struct _uattr_packet *attributes;
	int attr_cnt;
	/* if not NULL then the packet is a user attribute */
	u8 *attr_data;
	long attr_len;
	u8 *name_hash;
	int help_key_usage;
	u32 help_key_expire;
	int help_full_count;
	int help_marginal_count;
	/* expires at this date or 0 if not at all */
	u32 expire_date;
	/* list of preferences (may be NULL)*/
	struct {
		u8 pref_type;
		u8 pref_val;
	} *prefs;
	/* according to the self-signature */
	u32 created;
	/* From the ring trust packet. */
	u32 key_update;
	/* NULL or the URL of the last update origin. */
	char *update_url;
	/* From the ring trust packet. */
	u8 key_org;
	u8 self_sig_version;
	struct {
		unsigned mdc : 1;
		int ks_modify : 1;
		unsigned compacted : 1;
		/* 2 if set via the primary flag, 1 if calculated */
		int primary : 2;
		unsigned revoked : 1;
		int expired : 1;
	} flags;
	/* NULL or the result of mailbox_from_userid. */
	char *mbox;
	/*
	 * the text contained in the user id packet, which is normally the
	 * name and email address of the key holder.
	 * for convenience an extra Nul is always appended.
	 */
	char *uid_txt;
} UI_PACKET;

/* Public-Subkey Packet */
typedef struct _pubkey_packet PUBSUBKEY_PACKET;

/* User Attribute Packet */
typedef struct _uattr_packet {
	u8 attr_type;
	u8 const *attr_data;
	u32 len;
} UATTR_PACKET;

/* Sym. Encrypted and Integrity Protected Data Packet */
typedef struct _seipdata_packet {
	/* remaining length of encrypted data */
	u32 len;
	/*
	 * the first block size bytes of data are random data
	 * and the following two bytes are copies of the last two bytes
	 * of random data.
	 */
	int extra_len;
	/* whether new format is used */
	u8 new_ctb;
	/* indeterminate length (old) or partial body length headers (new) */
	u8 is_partial;
	/*
	 * 0 is disabled; otherwise the MDC method used
	 * currently only HASH_SHA1 is supported by GnuPG
	 */
	u8 mdc_method;
	/* data to be decrypted */
	u8 *seipdata;
} SEIPDATA_PACKET;

/* Modification Detection Code Packet */
typedef struct _mdcode_packet {
	u8 hash[20];
} MDCODE_PACKET;

/* Private or Experimental Values */
struct _prvt_packet {
	u8 const *priv_data;
};
typedef struct _prvt_packet PRVT0_PACKET;
typedef struct _prvt_packet PRVT1_PACKET;
typedef struct _prvt_packet PRVT2_PACKET;
typedef struct _prvt_packet PRVT3_PACKET;

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

/* packet header names for debug printing */
static char const *const header_formats[2] = {
	[FMT_OLD] = "FMT_OLD", [FMT_NEW] = "FMT_NEW",
};

/* packet tag names for debug printing */
static char const *const packet_types[64] = {
	[TAG_RSRVD] = "TAG_RSRVD", [TAG_PKESESS] = "TAG_PKESESS",
	[TAG_SIG] = "TAG_SIG", [TAG_SKESESS] = "TAG_SKESESS",
	[TAG_OPSIG] = "TAG_OPSIG", [TAG_SECKEY] = "TAG_SECKEY",
	[TAG_PUBKEY] = "TAG_PUBKEY", [TAG_SECSUBKEY] = "TAG_SECSUBKEY",
	[TAG_CDATA] = "TAG_CDATA", [TAG_SEDATA] = "TAG_SEDATA",
	[TAG_MARKER] = "TAG_MARKER", [TAG_LITDATA] = "TAG_LITDATA",
	[TAG_TRUST] = "TAG_TRUST", [TAG_UID] = "TAG_UID",
	[TAG_PUBSUBKEY] = "TAG_PUBSUBKEY", [TAG_UATTR] = "TAG_UATTR",
	[TAG_SEIPDATA] = "TAG_SEIPDATA", [TAG_MDCODE] = "TAG_MDCODE",
	[TAG_PRVT0] = "TAG_PRVT0", [TAG_PRVT1] = "TAG_PRVT1",
	[TAG_PRVT2] = "TAG_PRVT2", [TAG_PRVT3] = "TAG_PRVT3",
};

/* pubkey algorithm names for debug printing */
static char const *const pubkey_types[128] = {
	[PUB_RSA] = "PUB_RSA", [PUB_RSAENC] = "PUB_RSAENC",
	[PUB_RSASIG] = "PUB_RSASIG", [PUB_ELGAENC] = "PUB_ELGAENC",
	[PUB_DSA] = "PUB_DSA", [PUB_ELCURVE] = "PUB_ELCURVE",
	[PUB_ECDSA] = "PUB_ECDSA", [PUB_ELGA] = "PUB_ELGA",
	[PUB_DH] = "PUB_DH", [PUB_PRIV0] = "PUB_PRIV0",
	[PUB_PRIV1] = "PUB_PRIV1", [PUB_PRIV2] = "PUB_PRIV2",
	[PUB_PRIV3] = "PUB_PRIV3", [PUB_PRIV4] = "PUB_PRIV4",
	[PUB_PRIV5] = "PUB_PRIV5", [PUB_PRIV6] = "PUB_PRIV6",
	[PUB_PRIV7] = "PUB_PRIV7", [PUB_PRIV8] = "PUB_PRIV8",
	[PUB_PRIV9] = "PUB_PRIV9",
};

/* symmetric-key algorithm names for debug printing */
static char const *const symkey_types[128] = {
	[SYM_RAW] = "SYM_RAW", [SYM_IDEA] = "SYM_IDEA",
	[SYM_TDES] = "SYM_TDES", [SYM_CAST5] = "SYM_CAST5",
	[SYM_BLOWFISH] = "SYM_BLOWFISH", [SYM_RSRVD0] = "SYM_RSRVD0",
	[SYM_RSRVD1] = "SYM_RSRVD1", [SYM_AES128] = "SYM_AES128",
	[SYM_AES192] = "SYM_AES192", [SYM_AES256] = "SYM_AES256",
	[SYM_TWOFISH] = "SYM_TWOFISH", [SYM_PRIV0] = "SYM_PRIV0",
	[SYM_PRIV1] = "SYM_PRIV1", [SYM_PRIV2] = "SYM_PRIV2",
	[SYM_PRIV3] = "SYM_PRIV3", [SYM_PRIV4] = "SYM_PRIV4",
	[SYM_PRIV5] = "SYM_PRIV5", [SYM_PRIV6] = "SYM_PRIV6",
	[SYM_PRIV7] = "SYM_PRIV7", [SYM_PRIV8] = "SYM_PRIV8",
	[SYM_PRIV9] = "SYM_PRIV9",
};

/* compression algorithm names for debug printing */
static char const *const compression_types[128] = {
	[CMPR_RAW] = "CMPR_RAW", [CMPR_ZIP] = "CMPR_ZIP",
	[CMPR_ZLIB] = "CMPR_ZLIB", [CMPR_BZ2] = "CMPR_BZ2",
	[CMPR_PRIV0] = "CMPR_PRIV0", [CMPR_PRIV1] = "CMPR_PRIV1",
	[CMPR_PRIV2] = "CMPR_PRIV2", [CMPR_PRIV3] = "CMPR_PRIV3",
	[CMPR_PRIV4] = "CMPR_PRIV4", [CMPR_PRIV5] = "CMPR_PRIV5",
	[CMPR_PRIV6] = "CMPR_PRIV6", [CMPR_PRIV7] = "CMPR_PRIV7",
	[CMPR_PRIV8] = "CMPR_PRIV8", [CMPR_PRIV9] = "CMPR_PRIV9",
};

/* hash algorithm names for debug printing */
static char const *const hash_types[128] = {
	[HASH_MD5] = "HASH_MD5", [HASH_SHA1] = "HASH_SHA1",
	[HASH_RIPE] = "HASH_RIPE", [HASH_RSVRD0] = "HASH_RSVRD0",
	[HASH_RSVRD1] = "HASH_RSVRD1", [HASH_RSVRD3] = "HASH_RSVRD3",
	[HASH_RSVRD4] = "HASH_RSVRD4", [HASH_SHA256 ] = "HASH_SHA256 ",
	[HASH_SHA384 ] = "HASH_SHA384 ", [HASH_SHA512 ] = "HASH_SHA512 ",
	[HASH_SHA224 ] = "HASH_SHA224 ", [HASH_PRIV0] = "HASH_PRIV0",
	[HASH_PRIV1] = "HASH_PRIV1", [HASH_PRIV2] = "HASH_PRIV2",
	[HASH_PRIV3] = "HASH_PRIV3", [HASH_PRIV4] = "HASH_PRIV4",
	[HASH_PRIV5] = "HASH_PRIV5", [HASH_PRIV6] = "HASH_PRIV6",
	[HASH_PRIV7] = "HASH_PRIV7", [HASH_PRIV8] = "HASH_PRIV8",
	[HASH_PRIV9] = "HASH_PRIV9",
};

/* string-to-key usage conventions names for debug printing */
static char const *const s2k_types[256] = {
	[STR_RAW] = "STR_RAW", [STR_S2K1] = "STR_S2K1", [STR_S2K2] = "STR_S2K2",
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
	if (fclose(*out_file) == EOF)
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
