/*
 * t/testparse.c:	unit-test for parse.c
 *
 * AUTHORS:		Joey Pabalinas <alyptik@protonmail.com>
 *			Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#include "tap.h"
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

int main(void)
{
	/* by manually inspecting the key, we infer this is the actual data */
	int expected[] = {T_SECKEY, T_UID, T_SIG, T_SECSUBKEY, T_SIG};
	char const *vec_bin = "./t/4yyylmao.gpg";
	pgp_list pkts = {0};

	/* start test block */
	plan(8);

	/* tests */
	ok(read_pgp_bin(NULL, vec_bin, &pkts) > 0, "test binary parsing");
	ok(pkts.cnt == 5, "test finding 5 binary packets");
	for (size_t i = 0; i < pkts.cnt; i++) {
		HPRINT(pkts.list[i].pheader);
		ok((((pkts.list[i].pheader & 0x3c) >> 2) & expected[i]) != 0, "test header tag %zu", i);
	}
	ok(parse_pgp_packets(&pkts) > 0, "test successful parser dispatch");

	/* cleanup */
	free_pgp_list(&pkts);

	/* return handled */
	done_testing();
}
