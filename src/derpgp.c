/*
 * derpgp.c:	derpgp
 *
 * AUTHORS:	Joey Pabalinas <alyptik@protonmail.com>
 *		Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#include "base64.h"
#include "packet.h"
#include "parse.h"
#include <gcrypt.h>
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

PGP_LIST parse_opts(int argc, char **argv, char const *optstring, FILE **restrict out_file)
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

	/* process options */
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
			/* check for already opened file */
			if (*out_file)
				break;
			*out_file = xfopen(optarg, "wb");
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

/* cleanup wrapper for `atexit()/at_quick_exit()` */
static inline void cleanup(void)
{
	gcry_control(GCRYCTL_TERM_SECMEM, NULL);
}

int main(int argc, char **argv)
{
	FILE *out_file = NULL;
	char const *const optstring = "hvi:o:";
	PGP_LIST pkts = parse_opts(argc, argv, optstring, &out_file);

	/*
	 * Allocate a pool of 512k secure memory.  This makes the secure memory
	 * available and also drops privileges where needed.  Note that by
	 * using functions like gcry_xmalloc_secure and gcry_mpi_snew Libgcrypt
	 * may extend the secure memory pool with memory which lacks the
	 * property of not being swapped out to disk.
	 */
	if (!gcry_check_version(GCRYPT_VERSION))
		ERRX("`libgcrypt` version mismatch");
	gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
	gcry_control(GCRYCTL_INIT_SECMEM, 0x80000, NULL);
	gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
	/* register exit handlers */
	atexit(cleanup);
	at_quick_exit(cleanup);

	/* handle packets */
	parse_pgp_packets(&pkts);

	/* debug packet parsing */
	puts(GREEN "PGP packets found:" RST);
	for (size_t i = 0; i < pkts.cnt; i++) {
		int cur_tag = TAGBITS(pkts.list[i].pheader);
		HPRINT(pkts.list[i].pheader);
		printf(YELLOW "%-10s\n" RST, packet_types[cur_tag]);
		/* debug output */
		if (cur_tag == TAG_SECSUBKEY) {
			/* write to `-o` file if specified */
			fwrite(pkts.list[i].seckey.rsa.der_data, 1,
					pkts.list[i].seckey.rsa.der_len, FALLBACK(out_file, stderr));
		}
	}


	/* cleanup */
	free_pgp_list(&pkts);
	xfclose(&out_file);

	return 0;
}
