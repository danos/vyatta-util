/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 *
  Copyright (c) 2013 by Brocade Communications Systems, Inc.

   All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
*/

#ifndef VECTOR_H_
#define VECTOR_H_

#ifdef __cplusplus
extern "C" {
#endif

struct vector;

struct vector *vector_new(char *, size_t);
void vector_free(struct vector *);
const char *vector_next(struct vector *, const char *);
size_t vector_count(const struct vector *);

#ifdef __cplusplus
}
#endif

#endif
