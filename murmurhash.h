/*
 * Murmur Hash is in the public domain. This version from Peter Scott,
 * translated from the original version from Austin Appleby.
 */

#ifndef _MURMURHASH_H_
#define _MURMURHASH_H_

#include <stdint.h>

void MurmurHash3_x64_128(const void *key, const int len, const uint32_t seed, void *out);

#endif
