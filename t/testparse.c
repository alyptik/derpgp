/*
 * t/testparse.c:	unit-test for parse.c
 *
 * AUTHORS:		Joey Pabalinas <alyptik@protonmail.com>
 *			Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#include "tap.h"

int main(void)
{
	plan(1);

	ok(1 == 1, "ayy lmao");

	/* return handled */
	done_testing();
}
