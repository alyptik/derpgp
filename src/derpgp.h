/*
 * derpgp.h:	header for derpgp.c
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

#ifndef _DERPGP_H
#define _DERPGP_H 1

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/memfd.h>
#include <math.h>
#include <regex.h>
#include <signal.h>
#include <stdalign.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <uchar.h>
#include <unistd.h>
#include <wchar.h>

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int munmap(void *addr, size_t length);

extern char **environ;

#endif
