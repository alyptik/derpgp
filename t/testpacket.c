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

int main(void)
{
	char vec_bin[] = "./t/4yyylmao.gpg";
	pgp_list packets = {0};

	/* by manually inspecting the key, we infer this is the actual data */
	/* start test block */
	plan(5);

	/* tests */
	ok(1 == 1, "test ayy lmao");
	ok(read_pgp_bin(NULL, vec_bin, &packets) > 0, "test binary parsing");

	ok(packets.cnt == 5, "binary parsed the 5 available packets");
	ok((packets.list[0].pheader & (T_SECKEY <<2)) != 0, "The first header is a secret key header");

	ok(parse_pubkey_packet(&packets.list[0]) != 0);

	/* cleanup */
	free_pgp_list(&packets);

	/* return handled */
	done_testing();
}
