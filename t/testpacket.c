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
size_t (*const dispatch_table[64][2])(pgp_packet *restrict) = {
	/*
	 * {&parse_rsrvd_packet, &free_rsrvd_packet},
	 * {&parse_pkesess_packet, &free_pkesess_packet},
	 * {&parse_skesess_packet, &free_skesess_packet},
	 */
	{0}, {0}, {0},
	/*
	 * {&parse_opsig_packet, &free_opsig_packet},
	 * {&parse_seckey_packet, &free_seckey_packet},
	 * {&parse_pubkey_packet, &free_pubkey_packet},
	 */
	{0},
	{&parse_seckey_packet, &free_seckey_packet},
	{&parse_pubkey_packet, &free_pubkey_packet},
	/*
	 * {&parse_cdata_packet, &free_cdata_packet},
	 * {&parse_secsubkey_packet, &free_secsubkey_packet},
	 * {&parse_sedat_packet, &free_sedat_packet},
	 */
	{0}, {0}, {0},
	/*
	 * {&parse_marker_packet, &free_marker_packet},
	 * {&parse_litdata_packet, &free_litdata_packet},
	 * {&parse_trust_packet, &free_trust_packet},
	 */
	{0}, {0}, {0},
	/*
	 * {&parse_ui_packet, &free_ui_packet},
	 * {&parse_pubsubkey_packet, &free_pubsubkey_packet},
	 */
	{0}, {0},
	/* two placeholder indices */
	{0}, {0},
	/*
	 * {&parse_uattr_packet, &free_uattr_packet},
	 * {&parse_seipdata_packet, &free_seipdata_packet},
	 * {&parse_mdcode_packet, &free_mdcode_packet},
	 */
	{0}, {0}, {0},
	/* ten placeholder indices */
	{0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
	/* ten placeholder indices */
	{0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
	/*
	 * {&parse_prvt{0}_packet, &free_prvt{0}_pacet},
	 * {&parse_prvt1_packet, &free_prvt1_packet},
	 * {&parse_prvt2_packet, &free_prvt2_packet},
	 * {&parse_prvt3_packet, &free_prvt3_packet},
	 */
	{0}, {0}, {0}, {0},
};

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
extern inline size_t free_pubkey_packet(pgp_packet *restrict packet);
extern inline size_t free_seckey_packet(pgp_packet *restrict packet);
extern inline void free_pgp_list(pgp_list *restrict pkts);
extern inline void add_pgp_list(pgp_list *restrict list_struct, pgp_packet const *restrict packet);
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
	ok((packets.list[0].pheader & (T_SECKEY << 2)) != 0, "test secret key header match");
	ok((packets.list[3].pheader & (T_SECSUBKEY << 2)) != 0, "test secret subkey header match");
	ok(parse_seckey_packet(&packets.list[0]) > 0, "test successful sec key packet parsing");
	/* test vector doesn't have a public key */
	ok(parse_pubkey_packet(&packets.list[3]) > 0, "test successful public key packet parsing");

	/* cleanup */
	free_pubkey_packet(&packets.list[3]);
	/* test vector doesn't have a public key */
	free_pgp_list(&packets);

	/* return handled */
	done_testing();
}
