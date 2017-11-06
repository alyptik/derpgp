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

/* extern inline prototypes to prevent linker errors */
extern inline void xmalloc(void *restrict ptr, size_t sz, char const *msg);
extern inline void xcalloc(void *restrict ptr, size_t nmemb, size_t sz, char const *msg);
extern inline void xrealloc(void *restrict ptr, size_t sz, char const *msg);
extern inline size_t xfread(void *restrict ptr, size_t sz, size_t nmemb, FILE *restrict stream);
extern inline ptrdiff_t free_argv(char ***restrict argv);
extern inline void strmv(ptrdiff_t off, char *restrict dest, char const *restrict src);
extern inline ptrdiff_t free_str_list(str_list *restrict plist);
extern inline void init_str_list(str_list *restrict list_struct, char *restrict init_str);
extern inline void append_str(str_list *restrict list_struct, char const *restrict string, size_t pad);
extern inline void init_pgp_list(pgp_list *restrict list_struct);
extern inline void add_pgp_list(pgp_list *restrict list_struct, pgp_packet const *restrict packet);
extern inline void free_pgp_pubkey(pgp_packet *restrict packet);
extern inline void free_pgp_seckey(pgp_packet *restrict packet);
extern inline void free_pgp_list(pgp_list *restrict list_struct);
extern inline size_t read_pgp_bin(FILE *file_ctx, char const *restrict filename, pgp_list *restrict list);

int main(void)
{
	char const *vec_bin = "./t/4yyylmao.gpg";
	pgp_list packets = {0};

	/* start test block */
	plan(6);

	/* tests */
	ok(read_pgp_bin(NULL, vec_bin, &packets) > 0, "test binary parsing");
	ok(packets.cnt == 5, "test finding 5 binary packets");
	/* by manually inspecting the key, we infer this is the actual data */
	ok((packets.list[0].pheader & (T_SECKEY << 2)) != 0, "test finding secret key header");
	ok((packets.list[3].pheader & (T_SECSUBKEY << 2)) != 0, "test finding secret subkey header");
	ok(parse_seckey_packet(&packets.list[0]) > 0, "test successful sec key packet parsing");
	/* test vector doesn't have a public key */
	ok(parse_pubkey_packet(&packets.list[3]) > 0, "test successful public key packet parsing");

	/* cleanup */
	free_pgp_pubkey(&packets.list[3]);
	/* test vector doesn't have a public key */
	free_pgp_list(&packets);

	/* return handled */
	done_testing();
}
