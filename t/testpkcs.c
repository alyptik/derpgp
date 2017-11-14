/*
 * t/testpkcs.c:	unit-test for pkcs.c
 *
 * AUTHORS:		Joey Pabalinas <alyptik@protonmail.com>
 *			Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#include "tap.h"
#include "../src/base64.h"
#include "../src/pkcs.h"

int main(void)
{
	/* char const *const vec_bin = "./t/4yyylmao.gpg"; */
	char const *const vec_bin = "./t/nopasswd.gpg";
	PGP_LIST pkts = {0};

	/* start test block */
	plan(3);

	/* tests */
	(void)vec_bin, (void)pkts;
	ok(1, "test ayy lmao");
	ok(memcmp("YQ==", base64((u8 []){'a', 0, 0}), 4) == 0, "test correct base64 encodinag");
	ok(memcmp("abc", unbase64("YWJj"), 3) == 0, "test correct base64 decodinag");

	/* return handled */
	done_testing();
}
