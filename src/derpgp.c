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

/* silence linter */
int getopt_long(int ___argc, char *const ___argv[], char const *__shortopts, struct option const *__longopts, int *__longind);

/* extern inline prototypes to prevent linker errors */
extern inline void xmalloc(void *restrict ptr, size_t sz, char const *msg);
extern inline void xcalloc(void *restrict ptr, size_t nmemb, size_t sz, char const *msg);
extern inline void xrealloc(void *restrict ptr, size_t sz, char const *msg);
extern inline size_t xfread(void *restrict ptr, size_t sz, size_t nmemb, FILE *restrict stream);
extern inline ptrdiff_t free_argv(char ***restrict argv);
extern inline void strmv(ptrdiff_t off, char *restrict dest, char const *restrict src);
extern inline ptrdiff_t free_str_list(STR_LIST *restrict plist);
extern inline void init_str_list(STR_LIST *restrict list_struct, char *restrict init_str);
extern inline void append_str(STR_LIST *restrict list_struct, char const *restrict string, size_t pad);

PGP_LIST parse_opts(int argc, char **argv, char const *optstring)
{
	int opt;
	PGP_LIST pkts = {0};
	bool read_stdin = false;

	/* print an error if option not found */
	opterr = 1;
	/* reset option indices to reuse argv */
	option_index = 0;
	optind = 1;

	/* attempt to read standard input if part of a pipe */
	if (!isatty(STDIN_FILENO)) {
		read_pgp_bin(NULL, "/dev/stdin", &pkts);
		read_stdin = true;
	}

	while ((opt = getopt_long(argc, argv, optstring, long_opts, &option_index)) != -1) {
		switch (opt) {

		/* input file flag */
		case 'i':
			/* attempt to read standard input if argument is "-" */
			if (!strcmp(optarg, "-")) {
				/* don't read stdin twice */
				if (read_stdin)
					break;
				read_pgp_bin(NULL, "/dev/stdin", &pkts);
				read_stdin = true;
				break;
			}
			/* else read the file specified */
			read_pgp_bin(NULL, optarg, &pkts);
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

	return pkts;
}

int main(int argc, char **argv)
{
	char const *const optstring = "hvi:o:";
	PGP_LIST pkts = parse_opts(argc, argv, optstring);

	/* handle packets */
	parse_pgp_packets(&pkts);

	/* debug packet parsing */
	puts(GREEN "PGP packets found:" RST);
	for (size_t i = 0; i < pkts.cnt; i++) {
		int cur_tag = (pkts.list[i].pheader & 0x3c) >> 2;
		HPRINT(pkts.list[i].pheader);
		printf(YELLOW "%-10s\n" RST, packet_types[cur_tag]);
	}

	/* cleanup */
	free_pgp_list(&pkts);

	return 0;
}
