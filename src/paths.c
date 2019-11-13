/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 *
 * Copyright (c) 2014 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <argz.h>
#include <uriparser/Uri.h>
#include "paths.h"

/*argsToPath takes an argz array and returns a url encoded '/' separated string*/
char *args_to_path(char *args, size_t args_len) {
	size_t plen = 0;
	char *path = NULL;
	char *entry;

	argz_add(&path, &plen, "");
	for (entry = args; entry != NULL; entry = argz_next(args, args_len, entry)) {
		int sz = strlen(entry);
		char *cstr = (char *)malloc(sz * 6); //magic multiple from uriparser docs.
		uriEscapeA(entry, cstr, URI_FALSE, URI_TRUE);
		argz_add(&path, &plen, cstr);
		free(cstr);
        }

	argz_stringify(path, plen, '/');
	return path;
}

