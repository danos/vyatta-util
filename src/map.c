/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 *
 * Copyright (c) 2014 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <argz.h>
#include <envz.h>
#include <errno.h>
#include <stdlib.h>

#include "map.h"

struct map {
	char *z;
	size_t s;
};

struct map *map_new(char *argz, size_t argz_len)
{
	struct map *m = malloc(sizeof(struct map));
	if (m) {
		m->z = argz;
		m->s = argz_len;
	}
	return m;
}

void map_free(struct map *m)
{
	if (!m)
		return;
	free(m->z);
	free(m);
}

const char *map_next(struct map *m, const char *entry)
{
	if (!m) {
		errno = EFAULT;
		return NULL;
	}
	return argz_next(m->z, m->s, entry);
}

const char *map_get(struct map *m, const char *key)
{
	if (!m) {
		errno = EFAULT;
		return NULL;
	}
	return envz_get(m->z, m->s, key);
}
