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
	char const *vec_bin = "./t/4yyylmao.gpg";
	pgp_list packets = {0};

	/* by manually inspecting the key, we infer this is the actual data */
	int expected_pheaders[] = {
		T_SECKEY,
		T_UID,
		T_SIG,
		T_SECSUBKEY,
		T_SIG
	};

	/* start test block */
	plan(8);

	/* tests */
	ok(1 == 1, "test ayy lmao");
	ok(read_pgp_bin(NULL, vec_bin, &packets) > 0, "test binary parsing");

	ok(packets.cnt == 5, "binary parsed the 5 available packets");
	for (size_t i = 0; i < packets.cnt; i++) {
		HEX(packets.list[i].pheader);
		ok((packets.list[i].pheader & (expected_pheaders[i] << 2)) != 0,
				"header %u is the correct tag", i);
	}

	/* cleanup */
	free_pgp_list(&packets);

	/* return handled */
	done_testing();
}
