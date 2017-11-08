/*
 * derpgp.c:	derpgp
 *
 * AUTHORS:	Joey Pabalinas <alyptik@protonmail.com>
 *		Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#include "packet.h"
#include "parse.h"
#include <getopt.h>

/* silence linter */
int getopt_long(int ___argc, char *const ___argv[], char const *__shortopts, struct option const *__longopts, int *__longind);

/* static variables */
static struct option const long_opts[] = {
	{"help", no_argument, 0, 'h'},
	{"input", required_argument, 0, 'i'},
	{"output", required_argument, 0, 'o'},
	{"version", no_argument, 0, 'v'},
	{0}
};
static int option_index;

/* getopts variables */
extern char *optarg;
extern int optind, opterr, optopt;
extern char **environ;

void parse_opts(int argc, char **argv, char const *optstring)
{
	int opt;

	/* don't print an error if option not found */
	opterr = 1;
	/* reset option indices to reuse argv */
	option_index = 0;
	optind = 1;

	while ((opt = getopt_long(argc, argv, optstring, long_opts, &option_index)) != -1) {
		switch (opt) {

		/* input file flag */
		case 'i':
			/* TODO XXX: implement */
			break;

		/* output file flag */
		case 'o':
			/* TODO XXX: implement */
			break;

		/* version flag */
		case 'v':
			fprintf(stderr, "%s\n", VERSION_STRING);
			exit(0);
			/* unused break */
			break;

		/* usage and unrecognized flags */
		case 'h':
		case '?':
		default:
			fprintf(stderr, "%s %s %s\n", "Usage:", argv[0], USAGE_STRING);
			exit(0);
		}
	}
}

int main(int argc, char **argv)
{
	char const optstring[] = "hvi:o:";
	parse_opts(argc, argv, optstring);
	puts("derp derp derp");

	return 0;
}
