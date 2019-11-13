/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 *
 * Copyright (c) 2013-2014 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <argz.h>
#include <errno.h>
#include <stdlib.h>

#include "vector.h"

struct vector {
	char *z;
	size_t s;
};

struct vector *vector_new(char *argz, size_t argz_len)
{
	struct vector *v = malloc(sizeof(struct vector));
	if (v) {
		v->z = argz;
		v->s = argz_len;
	}
	return v;
}

void vector_free(struct vector *v)
{
	if (!v)
		return;
	free(v->z);
	free(v);
}

const char *vector_next(struct vector *v, const char *entry)
{
	if (!v) {
		errno = EFAULT;
		return NULL;
	}
	errno = 0;
	return argz_next(v->z, v->s, entry);
}

size_t vector_count(const struct vector *v)
{
	if (!v) {
		errno = EFAULT;
		return 0;
	}
	errno = 0;
	return argz_count(v->z, v->s);
}
