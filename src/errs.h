/*
 * errs.h:	exception wrappers
 *
 * AUTHORS:	Joey Pabalinas <alyptik@protonmail.com>
 *		Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 *
 * __OR__
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef ERRS_H
#define ERRS_H 1

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* errno, file, and lineno macros */
#define ESTR		strerror(errno), __FILE__, __LINE__
#define FSTR		__FILE__, __LINE__

/* warning macros */
#define WARN(X)		fprintf(stderr, "`%s`: [%s:%u] %s\n", ESTR, (X))
#define WARNX(X)	fprintf(stderr, "[%s:%u] %s\n", FSTR, (X))
#define WARNMSG(X, M)	fprintf(stderr, "`%s`: [%s:%u] %s %s\n", ESTR, (X), (M))
#define WARNXMSG(X, M)	fprintf(stderr, "[%s:%u] %s %s\n", FSTR, (X), (M))
#define WARNARR(X, Y)	fprintf(stderr, "`%s`: [%s:%u] %s[%zu]\n", ESTR, (X), (Y))
#define WARNXARR(X, Y)	fprintf(stderr, "[%s:%u] %s[%zu]\n", FSTR, (X), (Y))

/* error macros */
#define ERR(X)		do { fprintf(stderr, "`%s`: [%s:%u] %s\n", ESTR, (X)); exit(EXIT_FAILURE); } while (0)
#define ERRX(X)		do { fprintf(stderr, "[%s:%u] %s\n", FSTR, (X)); exit(EXIT_FAILURE); } while (0)
#define ERRMSG(X, M)	do { fprintf(stderr, "`%s`: [%s:%u] %s %s\n", ESTR, (X), (M)); exit(EXIT_FAILURE); } while (0)
#define ERRXMSG(X, M)	do { fprintf(stderr, "%s:%u %s %s\"\n", FSTR, (X), (M)); exit(EXIT_FAILURE); } while (0)
#define ERRARR(X, Y)	do { fprintf(stderr, "`%s`: [%s:%u] %s[%zu]\n", ESTR, (X), (Y)); exit(EXIT_FAILURE); } while (0)
#define ERRXARR(X, Y)	do { fprintf(stderr, "[%s:%u] %s[%zu]\n", FSTR, (X), (Y)); exit(EXIT_FAILURE); } while (0)

#endif
