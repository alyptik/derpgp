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
	char const *const vec_bin = "./t/4yyylmao.gpg";
	PGP_LIST pkts = {0};
	/* by manually inspecting the key, we infer this is the actual data */
	int expected[] = {T_SECKEY, T_UID, T_SIG, T_SECSUBKEY, T_SIG};

	/* start test block */
	plan(9);

	/* tests */
	ok(read_pgp_bin(NULL, vec_bin, &pkts) > 0, "test binary parsing");
	ok(pkts.cnt == 5, "test finding 5 binary packets");
	for (size_t i = 0; i < pkts.cnt; i++) {
		int cur_tag = TAGBITS(pkts.list[i].pheader);
		size_t header_len = snprintf(NULL, 0,
				RED "[%#x]\t" YELLOW "%-10s\t" RST,
				pkts.list[i].pheader, packet_types[cur_tag]);
		char pckt_str[header_len];
		snprintf(pckt_str, sizeof pckt_str,
				RED "[%#x]\t" YELLOW "%-10s\t" RST,
				pkts.list[i].pheader, packet_types[cur_tag]);
		ok(cur_tag == expected[i], "test header tag %zu %s" RST, i, pckt_str);
	}
	ok(parse_pgp_packets(&pkts) > 0, "test successful parser dispatch");
	lives_ok({free_pgp_list(&pkts);}, "test successful packet list cleanup");

	/* return handled */
	done_testing();
}
