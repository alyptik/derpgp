/*
 * t/testpacket.c:	unit-test for packet.c
 *
 * AUTHORS:		Joey Pabalinas <alyptik@protonmail.com>
 *			Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#include "tap.h"
#include "../src/packet.h"
#include "../src/parse.h"

/*
 * static function pointer array
 *
 * TODO XXX: implement remaining handlers
 */
size_t (*const dispatch_table[64][2])(PGP_PACKET *restrict) = {
	[T_RSRVD] = {0},
	[T_PKESESS] = {0},
	[T_SIG] = {0},
	[T_SKESESS] = {0},
	[T_OPSIG] = {0},
	[T_SECKEY] = {&parse_seckey_packet, &free_seckey_packet},
	[T_PUBKEY] = {&parse_pubkey_packet, &free_pubkey_packet},
	[T_SECSUBKEY] = {0},
	[T_CDATA] = {0},
	[T_SEDATA] = {0},
	[T_MARKER] = {0},
	[T_LITDATA] = {0},
	[T_TRUST] = {0},
	[T_UID] = {0},
	[T_PUBSUBKEY] = {0},
	[T_UATTR] = {0},
	[T_SEIPDATA] = {0},
	[T_MDCODE] = {0},
	[T_PRVT0] = {0},
	[T_PRVT1] = {0},
	[T_PRVT2] = {0},
	[T_PRVT3] = {0},
};

/* extern inline prototypes to prevent linker errors */
extern inline void xmalloc(void *restrict ptr, size_t sz, char const *msg);
extern inline void xcalloc(void *restrict ptr, size_t nmemb, size_t sz, char const *msg);
extern inline void xrealloc(void *restrict ptr, size_t sz, char const *msg);
extern inline size_t xfread(void *restrict ptr, size_t sz, size_t nmemb, FILE *restrict stream);
extern inline ptrdiff_t free_argv(char ***restrict argv);
extern inline void strmv(ptrdiff_t off, char *restrict dest, char const *restrict src);
extern inline ptrdiff_t free_str_list(STR_LIST *restrict plist);
extern inline void init_str_list(STR_LIST *restrict list_struct, char *restrict init_str);
extern inline void append_str(STR_LIST *restrict list_struct, char const *restrict string, size_t pad);
extern inline void init_pgp_list(PGP_LIST *restrict list_struct);
extern inline size_t free_pubkey_packet(PGP_PACKET *restrict packet);
extern inline size_t free_seckey_packet(PGP_PACKET *restrict packet);
extern inline void free_pgp_list(PGP_LIST *restrict pkts);
extern inline void add_pgp_list(PGP_LIST *restrict list_struct, PGP_PACKET const *restrict packet);
extern inline size_t read_pgp_bin(FILE *file_ctx, char const *restrict filename, PGP_LIST *restrict list);

int main(void)
{
	char const *vec_bin = "./t/4yyylmao.gpg";
	PGP_LIST packets = {0};

	/* start test block */
	plan(6);

	/* tests */
	ok(read_pgp_bin(NULL, vec_bin, &packets) > 0, "test binary parsing");
	ok(packets.cnt == 5, "test finding 5 binary packets");
	/* by manually inspecting the key, we infer this is the actual data */
	ok((packets.list[0].pheader & (T_SECKEY << 2)) != 0, "test secret key header match");
	ok((packets.list[0].pheader & (T_SECSUBKEY << 2)) != 0, "test secret subkey header match");
	ok(parse_pubkey_packet(&packets.list[0]) > 0, "test successful public key packet parsing");
	ok(parse_seckey_packet(&packets.list[0]) > 0, "test successful sec key packet parsing");

	/* cleanup */
	free_pgp_list(&packets);

	/* return handled */
	done_testing();
}
