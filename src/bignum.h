/*
 * bignum.h:	arbitrary precision math
 *
 * AUTHORS:	Joey Pabalinas <alyptik@protonmail.com>
 *		Santiago Torres <sangy@riseup.net>
 *
 * See LICENSE.md file for copyright and license details.
 */

#ifndef _BIGNUM_H
#define _BIGNUM_H 1

#include <stdio.h>
#include <stdlib.h>

/* maximum length bignum */
#define	MAXDIGITS 1024
/* positive sign bit */
#define PLUS 1
/* negative sign bit */
#define MINUS (-1)

typedef struct _bignum {
	/* represent the number */
	char digits[MAXDIGITS];
	/* 1 if positive, -1 if negative */
	int sign_bit;
	/* index of high-order digit */
	int last_digit;
} BIGNUM;

static inline void print_bignum(BIGNUM *n)
{
	if (n->sign_bit == MINUS)
		printf("- ");
	for (int i = n->last_digit; i >= 0; i--)
		printf("%c",'0'+ n->digits[i]);
	putchar('\n');
}

static inline void int_to_bignum(int s, BIGNUM *n)
{
	/* counter */
	int i;
	/* int to work with */
	int t;

	if (s >= 0)
		n->sign_bit = PLUS;
	else
		n->sign_bit = MINUS;

	for (i=0; i<MAXDIGITS; i++)
		n->digits[i] = 0;

	n->last_digit = -1;
	t = abs(s);

	while (t > 0) {
		n->last_digit ++;
		n->digits[ n->last_digit ] = (t % 10);
		t = t / 10;
	}

	if (s == 0) n->last_digit = 0;
}

static inline void initialize_bignum(BIGNUM *n)
{
	int_to_bignum(0,n);
}

static inline int max(int a, int b)
{
	return (a > b) ? a : b;
}

/*
 * c = a [operation] b
 */

static inline void zero_justify(BIGNUM *n)
{
	while ((n->last_digit > 0) && (n->digits[n->last_digit] == 0))
		n->last_digit --;

	/* hack to avoid -0 */
	if ((n->last_digit == 0) && (n->digits[0] == 0))
		n->sign_bit = PLUS;
}

static inline int compare_bignum(BIGNUM *a, BIGNUM *b)
{
	/* counter */
	int i;

	if ((a->sign_bit == MINUS) && (b->sign_bit == PLUS))
		return PLUS;
	if ((a->sign_bit == PLUS) && (b->sign_bit == MINUS))
		return MINUS;

	if (b->last_digit > a->last_digit)
		return PLUS * a->sign_bit;
	if (a->last_digit > b->last_digit)
		return MINUS * a->sign_bit;

	for (i = a->last_digit; i>=0; i--) {
		if (a->digits[i] > b->digits[i])
			return MINUS * a->sign_bit;
		if (b->digits[i] > a->digits[i])
			return PLUS * a->sign_bit;
	}

	return 0;
}

/* forward declaration */
static inline void subtract_bignum(BIGNUM *a, BIGNUM *b, BIGNUM *c);

static inline void add_bignum(BIGNUM *a, BIGNUM *b, BIGNUM *c)
{
	int carry;			/* carry digit */
	int i;				/* counter */

	initialize_bignum(c);

	if (a->sign_bit == b->sign_bit) c->sign_bit = a->sign_bit;
	else {
		if (a->sign_bit == MINUS) {
			a->sign_bit = PLUS;
			subtract_bignum(b,a,c);
			a->sign_bit = MINUS;
		} else {
			b->sign_bit = PLUS;
			subtract_bignum(a,b,c);
			b->sign_bit = MINUS;
		}
		return;
	}

	c->last_digit = max(a->last_digit,b->last_digit)+1;
	carry = 0;

	for (i=0; i<=(c->last_digit); i++) {
		c->digits[i] = (char) (carry+a->digits[i]+b->digits[i]) % 10;
		carry = (carry + a->digits[i] + b->digits[i]) / 10;
	}

	zero_justify(c);
}

static inline void subtract_bignum(BIGNUM *a, BIGNUM *b, BIGNUM *c)
{
	/* has anything been borrowed? */
	int borrow;
	/* placeholder digit */
	int v;
	/* counter */
	int i;

	initialize_bignum(c);

	if ((a->sign_bit == MINUS) || (b->sign_bit == MINUS)) {
		b->sign_bit = -1 * b->sign_bit;
		add_bignum(a,b,c);
		b->sign_bit = -1 * b->sign_bit;
		return;
	}

	if (compare_bignum(a,b) == PLUS) {
		subtract_bignum(b,a,c);
		c->sign_bit = MINUS;
		return;
	}

	c->last_digit = max(a->last_digit,b->last_digit);
	borrow = 0;

	for (i=0; i<=(c->last_digit); i++) {
		v = (a->digits[i] - borrow - b->digits[i]);
		if (a->digits[i] > 0)
			borrow = 0;
		if (v < 0) {
			v = v + 10;
			borrow = 1;
		}

		c->digits[i] = (char) v % 10;
	}

	zero_justify(c);
}

static inline void digit_shift(BIGNUM *n, int d)		/* multiply n by 10^d */
{
	int i;				/* counter */

	if ((n->last_digit == 0) && (n->digits[0] == 0)) return;

	for (i=n->last_digit; i>=0; i--)
		n->digits[i+d] = n->digits[i];

	for (i=0; i<d; i++) n->digits[i] = 0;

	n->last_digit = n->last_digit + d;
}

static inline void multiply_bignum(BIGNUM *a, BIGNUM *b, BIGNUM *c)
{
	BIGNUM row;			/* represent shifted row */
	BIGNUM tmp;			/* placeholder BIGNUM */
	int i,j;			/* counters */

	initialize_bignum(c);

	row = *a;

	for (i=0; i<=b->last_digit; i++) {
		for (j=1; j<=b->digits[i]; j++) {
			add_bignum(c,&row,&tmp);
			*c = tmp;
		}
		digit_shift(&row,1);
	}

	c->sign_bit = a->sign_bit * b->sign_bit;

	zero_justify(c);
}


static inline void divide_bignum(BIGNUM *a, BIGNUM *b, BIGNUM *c)
{
	/* represent shifted row */
	BIGNUM row;
	/* placeholder BIGNUM */
	BIGNUM tmp;
	/* temporary signs */
	int asign, bsign;
	/* counters */
	int i;

	initialize_bignum(c);

	c->sign_bit = a->sign_bit * b->sign_bit;

	asign = a->sign_bit;
	bsign = b->sign_bit;

	a->sign_bit = PLUS;
	b->sign_bit = PLUS;

	initialize_bignum(&row);
	initialize_bignum(&tmp);

	c->last_digit = a->last_digit;

	for (i=a->last_digit; i>=0; i--) {
		digit_shift(&row,1);
		row.digits[0] = a->digits[i];
		c->digits[i] = 0;
		while (compare_bignum(&row,b) != PLUS) {
			c->digits[i] ++;
			subtract_bignum(&row,b,&tmp);
			row = tmp;
		}
	}

	zero_justify(c);

	a->sign_bit = asign;
	b->sign_bit = bsign;
}

static inline void modulo_bignum(BIGNUM *a, BIGNUM *b, BIGNUM *c)
{
	/* represent shifted row */
	BIGNUM row;
	/* placeholder BIGNUM */
	BIGNUM tmp;
	/* temporary signs */
	int asign, bsign;
	/* counters */
	int i;

	initialize_bignum(c);

	c->sign_bit = a->sign_bit * b->sign_bit;

	asign = a->sign_bit;
	bsign = b->sign_bit;

	a->sign_bit = PLUS;
	b->sign_bit = PLUS;

	initialize_bignum(&row);
	initialize_bignum(&tmp);

	c->last_digit = a->last_digit;

	for (i=a->last_digit; i>=0; i--) {
		digit_shift(&row,1);
		row.digits[0] = a->digits[i];
		c->digits[i] = 0;
		while (compare_bignum(&row,b) != PLUS) {
			c->digits[i] ++;
			subtract_bignum(&row,b,&tmp);
			row = tmp;
		}
	}

	*c = tmp;

	zero_justify(c);

	a->sign_bit = asign;
	b->sign_bit = bsign;
}

#endif
