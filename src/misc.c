/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 *
 * Copyright (c) 2014 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <regex.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
re_match(const char *string, char *pattern)
{
  int status;
  regex_t re;
  if (regcomp(&re, pattern, REG_EXTENDED|REG_NOSUB) != 0) {
      return  0;    
  }
  status = regexec(&re, string, (size_t) 0, NULL, 0);
  regfree(&re);
  if (status != 0) {
      return  0;   
  }
  return 1;
}
