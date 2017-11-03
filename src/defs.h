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
#define HTOLE16(DATA)		(((DATA)[1]) | ((DATA)[0] << 0x08))
#define HTOLE32(DATA)		(((DATA)[3]) | ((DATA)[2] << 0x08) | ((DATA)[1] << 0x10) | ((DATA)[0] << 0x18))
#define HEX(X)			printf("[%#x] ", (X))

/* global version and usage strings */

#define VERSION_STRING	"DerpGP v0.0.1"
#define USAGE_STRING	"[-hptvw] [(-a|-i)“<asm.s>”] [-c“<compiler>”] [-e“<code>”] " \
	"[-l“<libs>”] [-I“<includes>”] [-o“<out.c>”]\n\t" \
	"-a,--att:\t\tName of the file to output AT&T-dialect assembler code to\n\t" \
	"-c,--cc:\t\tSpecify alternate compiler\n\t" \
	"-e,--eval:\t\tEvaluate the following argument as C code\n\t" \
	"-h,--help:\t\tShow help/usage information\n\t" \
	"-i,--intel:\t\tName of the file to output Intel-dialect assembler code to\n\t" \
	"-o,--output:\t\tName of the file to output C source code to\n\t" \
	"-p,--parse:\t\tDisable addition of dynamic library symbols to readline completion\n\t" \
	"-t,--tracking:\t\tToggle variable tracking\n\t" \
	"-v,--version:\t\tShow version information\n\t" \
	"-w,--warnings:\t\tCompile with ”-pedantic -Wall -Wextra” flags\n\t" \
	"-l:\t\t\tLink against specified library (flag can be repeated)\n\t" \
	"-I:\t\t\tSearch directory for header files (flag can be repeated)\n" \
	"Input lines prefixed with a “;” are used to control internal state\n\t" \
	";a[tt]:\t\t\tToggle -a (output AT&T-dialect assembler code) flag\n\t" \
	";f[unction]:\t\tDefine a function (e.g. “;f void bork(void) { puts(\"wark\"); }”)\n\t" \
	";h[elp]:\t\tShow help\n\t" \
	";i[ntel]:\t\tToggle -a (output Intel-dialect assembler code) flag\n\t" \
	";m[acro]:\t\tDefine a macro (e.g. “;m #define SWAP2(X) ((((X) >> 8) & 0xff) | (((X) & 0xff) << 8))”)\n\t" \
	";o[utput]:\t\tToggle -o (output C source code) flag\n\t" \
	";p[arse]:\t\tToggle -p (shared library parsing) flag\n\t" \
	";q[uit]:\t\tExit CEPL\n\t" \
	";r[eset]:\t\tReset CEPL to its initial program state\n\t" \
	";t[racking]:\t\tToggle variable tracking\n\t" \
	";u[ndo]:\t\tIncremental pop_history (can be repeated)\n\t" \
	";w[arnings]:\t\tToggle -w (pedantic warnings) flag"
#define	RED		"\\033[31m"
#define	GREEN		"\\033[32m"
#define	YELLOW		"\\033[33m"
#define	RST		"\\033[00m"
/* page size for buffer count */
#define PAGE_SIZE	sysconf(_SC_PAGESIZE)
/* max possible types */
#define TNUM		7
/* max eval string length */
#define EVAL_LIMIT	4096
/* `strmv() `concat constant */
#define CONCAT		(-1)
/* `malloc()` size ceiling */
#define ARRAY_MAX	(SIZE_MAX / 2 - 1)

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
enum {
	/* packet formats */
	F_OLD = 0x00,
	F_NEW = 0x01,
};

/* packet tags */
enum {
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
enum {
	L_ONE = 0x00,
	L_TWO = 0x01,
	L_FOUR = 0x02,
	L_OTHER = 0x03,
};
/* TODO XXX: add support for new format packet headers */

/* structures */

/* Multi precision integers */
typedef struct _mpi {
	u16 length;
	u8 *data;
} mpi;

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
		/* Reserved - a packet tag MUST NOT have this value */
		struct { void *decoded; } rsrvd;
		/* Public-Key Encrypted Session Key Packet */
		struct { void *decoded; } pkesess;
		/* Symmetric-Key Encrypted Session Key Packet */
		struct { void *decoded; } skesess;
		/* One-Pass Signature Packet */
		struct { void *decoded; } opsig;
		/* Secret-Key Packet */
		struct {
			u8 string_to_key;
			u8 sym_encryption_algo;
			u8 *IV;
			mpi exponent_d;
			mpi prime_p;
			mpi prime_q;
			mpi mult_inverse;
			u16 checksum;
		} seckey;
		/* Public-Key Packet
		 * FIXME: we only support V4 :>
		 */
		struct {
			/* NOTE: must be always 4 (or 3 in the future) */
			u8 version;
			/* posix timestamp */
			u32 timestamp;
			/* 1 for RSA, 2 for DSA */
			u8 algorithm;
			mpi modulus_n;
			mpi exponent;
		} pubkey;
		/* Secret-Subkey Packet */
		struct { void *decoded; } secsubkey;
		/* Compressed Data Packet */
		struct { void *decoded; } cdata;
		/* Symmetrically Encrypted Data Packet */
		struct { void *decoded; } sedat;
		/* Marker Packet */
		struct { void *decoded; } marker;
		/* Literal Data Packet */
		struct { void *decoded; } litdata;
		/* Trust Packet */
		struct { void *decoded; } trust;
		/* User ID Packet */
		struct { void *decoded; } ui;
		/* Public-Subkey Packet */
		struct { void *decoded; } pubsubkey;
		/* User Attribute Packet */
		struct { void *decoded; } uattr;
		/* Sym. Encrypted and Integrity Protected Data Packet */
		struct { void *decoded; } seipdata;
		/* Modification Detection Code Packet */
		struct { void *decoded; } mdcode;
		/* Private or Experimental Values */
		struct { void *decoded; } prvt0;
		struct { void *decoded; } prvt1;
		struct { void *decoded; } prvt2;
		struct { void *decoded; } prvt3;
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
	size_t cnt;
	if (!argv || !*argv)
		return -1;
	for (cnt = 0; (*argv)[cnt]; cnt++)
		free((*argv)[cnt]);
	free(*argv);
	*argv = NULL;
	return cnt;
}

/* emulate `strcat()` if `off < 0`, else copy `src` to `dest` at offset `off` */
static inline void strmv(ptrdiff_t off, char *restrict dest, char const *restrict src) {
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

static inline ptrdiff_t free_str_list(str_list *restrict plist)
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

static inline void init_str_list(str_list *restrict list_struct, char *restrict init_str)
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

static inline void append_str(str_list *restrict list_struct, char const *restrict string, size_t pad)
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
