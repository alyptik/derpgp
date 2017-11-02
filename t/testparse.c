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
	char vec_bin[] = "./t/4yyylmao.gpg";
	pgp_list packets = {0};

	/* start test block */
	plan(2);

	/* tests */
	ok(1 == 1, "ayy lmao");
	ok(read_pgp_bin(NULL, vec_bin, &packets) > 0, "test binary parsing");

	/* cleanup */
	free_pgp_list(&packets);

	/* return handled */
	done_testing();
}
