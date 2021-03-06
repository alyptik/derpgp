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
	char const *const vec_bin[2] = {
		"./t/nopasswd.gpg",
		"./t/4yyylmao.gpg",
	};

	/* start test block */
	plan(14);

	/* tests */
	for (size_t i = 0; i < ARRLEN(vec_bin); i++) {
		PGP_LIST pkts = {0};
		ok(read_pgp_bin(NULL, vec_bin[i], &pkts) > 0, "test binary parsing");
		ok(pkts.cnt == 5, "test finding 5 binary pkts");
		/* by manually inspecting the key, we infer this is the actual data */
		ok(TAGBITS(pkts.list[0].pheader) == TAG_SECKEY, "test secret key header match");
		ok(TAGBITS(pkts.list[3].pheader) == TAG_SECSUBKEY, "test secret subkey header match");
		ok(parse_pubkey_packet(&pkts.list[0]) > 0, "test successful public key packet parsing");
		ok(parse_seckey_packet(&pkts.list[3]) > 0, "test successful sec key packet parsing");
		lives_ok({free_pgp_list(&pkts);}, "test successful packet list cleanup");
	}

	/* return handled */
	done_testing();
}
