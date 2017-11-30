/*
 * t/testparse.c:	unit-test for parse.c
 *
 * AUTHORS:		Joey Pabalinas <alyptik@protonmail.com>
 *			Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#include "tap.h"
#include "../src/base64.h"
#include "../src/parse.h"

int main(void)
{
	/* by manually inspecting the key, we infer this is the actual data */
	char const *const vec_bin[2] = {
		"./t/nopasswd.gpg",
		"./t/4yyylmao.gpg",
	};
	int expected[] = {
		TAG_SECKEY, TAG_UID,
		TAG_SIG, TAG_SECSUBKEY,
		TAG_SIG
	};

	/* start test block */
	plan(18);

	/* tests */
	for (size_t i = 0; i < ARRLEN(vec_bin); i++) {
		PGP_LIST pkts = {0};
		ok(read_pgp_bin(NULL, vec_bin[i], &pkts) > 0, "test binary parsing");
		ok(pkts.cnt == 5, "test finding 5 binary packets");
		for (size_t j = 0; j < pkts.cnt; j++) {
			int cur_tag = TAGBITS(pkts.list[j].pheader);
			size_t header_len = snprintf(NULL, 0,
					RED "[%#x]\t" YELLOW "%-10s\t" RST,
					pkts.list[j].pheader, packet_types[cur_tag]);
			char pckt_str[header_len];
			snprintf(pckt_str, sizeof pckt_str,
					RED "[%#x]\t" YELLOW "%-10s\t" RST,
					pkts.list[j].pheader, packet_types[cur_tag]);
			ok(cur_tag == expected[j], "test header tag %zu %s" RST, j, pckt_str);
		}
		ok(parse_pgp_packets(&pkts) > 0, "test successful parser dispatch");
		lives_ok({free_pgp_list(&pkts);}, "test successful packet list cleanup");
	}

	/* return handled */
	done_testing();
}
