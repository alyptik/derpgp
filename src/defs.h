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
#include <stdint.h>
#include <unistd.h>

/* macros */

#define FALLBACK(ARG, DEF)	((ARG) ? (ARG) : (DEF))
#define BETOH16(DATA)		(((DATA)[1]) | ((DATA)[0] << 0x08))
#define BETOH32(DATA)		(((DATA)[3]) | ((DATA)[2] << 0x08) | ((DATA)[1] << 0x10) | ((DATA)[0] << 0x18))
#define HPRINT(VAL)		printf("[%#x] ", (VAL))

/* global version and usage strings */

#define VERSION_STRING		"DerpGP v0.0.1"
#define USAGE_STRING		"[-hv] [-i“<in.gpg>”] [-o“<out.pem>”]\n\t" \
	"-h,--help:\t\tShow help/usage information\n\t" \
	"-i,--input:\t\tName of the file to use for input\n\t" \
	"-o,--output:\t\tName of the file to use for output\n\t" \
	"-v,--version:\t\tShow version information\n\t" \
#define	RED			"\\033[31m"
#define	GREEN			"\\033[32m"
#define	YELLOW			"\\033[33m"
#define	RST			"\\033[00m"
/* page size for buffer count */
#define PAGE_SIZE		sysconf(_SC_PAGESIZE)
/* max eval string length */
#define EVAL_LIMIT		4096
/* `strmv() `concat constant */
#define CONCAT			(-1)
/* `malloc()` size ceiling */
#define ARRAY_MAX		(SIZE_MAX / 2 - 1)

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
	T_SEDATA= 0x09,
	/* Marker Packet */
	T_MARKER = 0x0a,
	/* Literal Data Packet */
	T_LITDATA = 0x0b,
	/* Trust Packet */
	T_TRUST = 0x0c,
	/* User ID Packet */
	T_UID= 0x0d,
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
	T_RSA = 0x01,
};

/* string-to-key usage conventions */
enum s2k_conventions {
	T_RAW = 0x00,
	T_S2K1 = 0xfe,
	T_S2K2 = 0xff,
};

/* structures */

/* Multi precision integers */
typedef struct _mpi {
	u16 length;
	u8 *mdata;
} mpi;

/*
 * pgp packet types
 */

/* Reserved - a packet tag MUST NOT have this value */
typedef struct  _rsrvd_packet {
	u8 *octets;
} rsrvd_packet;

/* Public-Key Encrypted Session Key Packet */
typedef struct  _pkesess_packet {
	u8 *octets;
} pkesess_packet;

/* Symmetric-Key Encrypted Session Key Packet */
typedef struct  _skesess_packet {
	u8 *octets;
} skesess_packet;

/* One-Pass Signature Packet */
typedef struct  _opsig_packet {
	u8 *octets;
} opsig_packet;

/* Secret-Key Packet */
typedef struct  _seckey_packet {
	u8 string_to_key;
	u8 sym_encryption_algo;
	u8 *iv;
	mpi exponent_d;
	mpi prime_p;
	mpi prime_q;
	mpi mult_inverse;
	u16 checksum;
} seckey_packet;

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
	mpi modulus_n;
	mpi exponent;
} pubkey_packet;

/* Secret-Subkey Packet */
typedef struct  _secsubkey_packet {
	u8 *octets;
} secsubkey_packet;

/* Compressed Data Packet */
typedef struct  _cdata_packet {
	u8 *octets;
} cdata_packet;

/* Symmetrically Encrypted Data Packet */
typedef struct  _sedat_packet {
	u8 *octets;
} sedat_packet;

/* Marker Packet */
typedef struct  _marker_packet {
	u8 *octets;
} marker_packet;

/* Literal Data Packet */
typedef struct  _litdata_packet {
	u8 *octets;
} litdata_packet;

/* Trust Packet */
typedef struct  _trust_packet {
	u8 *octets;
} trust_packet;

/* User ID Packet */
typedef struct  _ui_packet {
	u8 *octets;
} ui_packet;

/* Public-Subkey Packet */
typedef struct  _pubsubkey_packet {
	u8 *octets;
} pubsubkey_packet;

/* User Attribute Packet */
typedef struct  _uattr_packet {
	u8 *octets;
} uattr_packet;

/* Sym. Encrypted and Integrity Protected Data Packet */
typedef struct  _seipdata_packet {
	u8 *octets;
} seipdata_packet;

/* Modification Detection Code Packet */
typedef struct  _mdcode_packet {
	u8 *octets;
} mdcode_packet;

/* Private or Experimental Values */
typedef struct  _prvt0_packet {
	u8 *octets;
} prvt0_packet;
typedef struct  _prvt1_packet {
	u8 *octets;
} prvt1_packet;
typedef struct  _prvt2_packet {
	u8 *octets;
} prvt2_packet;
typedef struct  _prvt3_packet {
	u8 *octets;
} prvt3_packet;

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
		rsrvd_packet rsrvd;
		pkesess_packet pkesess;
		skesess_packet skesess;
		opsig_packet opsig;
		seckey_packet seckey;
		pubkey_packet pubkey;
		secsubkey_packet secsubkey;
		cdata_packet cdata;
		sedat_packet sedat;
		marker_packet marker;
		litdata_packet litdata;
		trust_packet trust;
		ui_packet ui;
		pubsubkey_packet pubsubkey;
		uattr_packet uattr;
		seipdata_packet seipdata;
		mdcode_packet mdcode;
		prvt0_packet prvt0;
		prvt1_packet prvt1;
		prvt2_packet prvt2;
		prvt3_packet prvt3;
	};
} pgp_packet;

/* struct definition for dynamic array of pgp structs */
typedef struct _pgp_list {
	size_t cnt, max;
	pgp_packet *list;
} pgp_list;

/* struct definition for NULL-terminated string dynamic array */
typedef struct _str_list {
	size_t cnt, max;
	char **list;
} str_list;

/* `malloc()` wrapper */
inline void xmalloc(void *restrict ptr, size_t sz, char const *msg)
{
	/* sanity check */
	if (!ptr)
		return;
	if (!(*(void **)ptr = malloc(sz)))
		ERR(msg ? msg : "(nil)");
}

/* `calloc()` wrapper */
inline void xcalloc(void *restrict ptr, size_t nmemb, size_t sz, char const *msg)
{
	/* sanity check */
	if (!ptr)
		return;
	if (!(*(void **)ptr = calloc(nmemb, sz)))
		ERR(msg ? msg : "(nil)");
}

/* `realloc()` wrapper */
inline void xrealloc(void *restrict ptr, size_t sz, char const *msg)
{
	void *tmp;
	/* sanity check */
	if (!ptr)
		return;
	if (!(tmp = realloc(*(void **)ptr, sz)))
		ERR(msg ? msg : "(nil)");
	*(void **)ptr = tmp;
}

/* `fread()` wrapper */
inline size_t xfread(void *restrict ptr, size_t sz, size_t nmemb, FILE *restrict stream)
{
	size_t cnt;
	if ((cnt = fread(ptr, sz, nmemb, stream)) < nmemb)
		return 0;
	return cnt;
}

/* recursive free */
inline ptrdiff_t free_argv(char ***restrict argv)
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
inline void strmv(ptrdiff_t off, char *restrict dest, char const *restrict src)
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

inline ptrdiff_t free_str_list(str_list *restrict plist)
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

inline void init_str_list(str_list *restrict list_struct, char *restrict init_str)
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

inline void append_str(str_list *restrict list_struct, char const *restrict string, size_t pad)
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
