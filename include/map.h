/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 *
  Copyright (c) 2013 by Brocade Communications Systems, Inc.

   All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
*/

#ifndef MAP_H_
#define MAP_H_

#ifdef __cplusplus
extern "C" {
#endif

struct map;

struct map *map_new(char *, size_t);
void map_free(struct map *);
const char *map_next(struct map *, const char *);
const char *map_get(struct map *, const char *);

#ifdef __cplusplus
}
#endif

#endif
