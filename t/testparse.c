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

int main(void)
{
	/* by manually inspecting the key, we infer this is the actual data */
	int expected[] = {T_SECKEY, T_UID, T_SIG, T_SECSUBKEY, T_SIG};
	char const *vec_bin = "./t/4yyylmao.gpg";
	pgp_list pkts = {0};

	/* start test block */
	plan(7);

	/* tests */
	ok(read_pgp_bin(NULL, vec_bin, &pkts) > 0, "test binary parsing");
	ok(pkts.cnt == 5, "test finding 5 binary packets");
	for (size_t i = 0; i < pkts.cnt; i++) {
		HPRINT(pkts.list[i].pheader);
		ok((pkts.list[i].pheader & (expected[i] << 2)) != 0, "test header tag %zu", i);
	}

	/* cleanup */
	free_pgp_list(&pkts);

	/* return handled */
	done_testing();
}
