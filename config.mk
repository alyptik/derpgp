#
# config.mk:	Makefile configuration variables
#
# AUTHORS:	Joey Pabalinas <alyptik@protonmail.com>
#		Santiago Torres <sangy@riseup.net>
#
# See LICENSE.md file for copyright and license details.

# optional
DESTDIR ?=
PREFIX ?= /usr/local
CC ?= gcc
OLVL ?= -O2
CFLAGS ?= -pipe -fstack-protector-strong
LDFLAGS ?= -pipe -fstack-protector-strong

# mandatory
LD = $(CC)
DEBUG_CFLAGS = $(DEBUG)
DEBUG_LDFLAGS = $(DEBUG)
MANPAGE = $(TARGET).1
MKALL = $(MKCFG) $(DEP)
OBJ = $(SRC:.c=.o)
TOBJ = $(TSRC:.c=.o)
DEP = $(SRC:.c=.d) $(TSRC:.c=.d)
BNOBJ = $(BNTEST:=.o)
TEST = $(filter-out $(BNTEST),$(filter-out $(PARSE),$(filter-out $(TAP),$(TSRC:.c=))))
UTEST = $(filter-out src/$(TARGET).o,$(SRC:.c=.o))
SRC := $(wildcard src/*.c)
TSRC := $(wildcard t/*.c)
HDR := $(wildcard src/*.h) $(wildcard t/*.h)
DEBUG := -pg -Og -ggdb3 -no-pie -fno-inline -Wfloat-equal -Wrestrict -Wshadow
CPPFLAGS := -D_FORTIFY_SOURCE=2 -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -MMD -MP
LIBS :=
TARGET := derpgp
TAP := t/tap
PARSE := t/testparse
BNTEST := t/factorial t/golden t/load_cmp t/randomized t/rsa t/test_div_algo
BINDIR := bin
MANDIR := share/man/man1
MKALL += Makefile debug.mk
DEBUG += -fno-builtin -fno-common -fprofile-generate=p -fsanitize=address,alignment,leak,undefined -fverbose-asm
CFLAGS += -fno-align-functions -fno-align-jumps -fno-align-labels -fno-align-loops -fno-strict-aliasing
CFLAGS += -flto -fPIC -fuse-linker-plugin -fuse-ld=gold -pedantic-errors -std=c11
CFLAGS += -Wall -Wextra -Wno-missing-field-initializers -Wstrict-overflow
LDFLAGS += -fno-align-functions -fno-align-jumps -fno-align-labels -fno-align-loops -fno-strict-aliasing
LDFLAGS += -flto -fPIC -fuse-linker-plugin -fuse-ld=gold
LDFLAGS += -Wl,-O2,-z,relro,-z,now,--sort-common,--as-needed

# vi:ft=make:
