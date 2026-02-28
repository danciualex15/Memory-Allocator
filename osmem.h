/* SPDX-License-Identifier: BSD-3-Clause */

#pragma once

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include "printf.h"

void *cs_malloc(size_t size);
void cs_free(void *ptr);
void *cs_calloc(size_t nmemb, size_t size);
void *cs_realloc(void *ptr, size_t size);
