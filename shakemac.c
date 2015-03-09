/** shake256-mac
 *
 * COPYRIGHT 2015
 *
 * A single-file implementation of Shake256 and a padded prefix-MAC
 * mode, with optional state caching.
 *
 * Authors: 
 *   David Leon Gil (coruus@gmail.com)
 *   Yahoo! Inc.
 * Contributors:
 *   David Leon Gil (dgil@yahoo-inc.com)
 *
 * License: Apache 2
 *
 * Canonical version at https://github.com/coruus/keccak-tiny
 */
#define  _KECCAK_SPONGE_INTERNAL
#include "shakemac.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* For future compilers that support it: */
// static_assert(sizeof(keccak_sponge_opaque) >= sizeof(keccak_sponge));
// static_assert(alignof(keccak_sponge_opaque) >= alignof(keccak_sponge));

#ifndef memset_s
#define memset_s(d, dlen, v, len) memset(d, v, dlen)
#endif 
/*** The Keccak-f[1600] permutation ***/

/** Constants. **/
static const uint8_t rho[24] = {1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
                                27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};
static const uint8_t pi[24] = {10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                               15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1};
static const uint64_t RC[24] = {1ULL,
                                0x8082ULL,
                                0x800000000000808aULL,
                                0x8000000080008000ULL,
                                0x808bULL,
                                0x80000001ULL,
                                0x8000000080008081ULL,
                                0x8000000000008009ULL,
                                0x8aULL,
                                0x88ULL,
                                0x80008009ULL,
                                0x8000000aULL,
                                0x8000808bULL,
                                0x800000000000008bULL,
                                0x8000000000008089ULL,
                                0x8000000000008003ULL,
                                0x8000000000008002ULL,
                                0x8000000000000080ULL,
                                0x800aULL,
                                0x800000008000000aULL,
                                0x8000000080008081ULL,
                                0x8000000000008080ULL,
                                0x80000001ULL,
                                0x8000000080008008ULL};

/** Keccak-f[1600] **/

/* Helper macros to unroll the permutation. */
#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))
#define REPEAT6(e) e e e e e e
#define REPEAT24(e) REPEAT6(e e e e)
#define REPEAT5(e) e e e e e
#define FOR5(v, s, e) \
  v = 0;              \
  REPEAT5(e; v += s;)

static inline void keccakf(void* state) {
  uint64_t* a = (uint64_t*)state;
  uint64_t b[5] = {0};
  uint64_t t = 0;
  uint8_t x, y;

  for (int i = 0; i < 24; i++) {
    // Theta
    FOR5(x, 1, b[x] = 0; FOR5(y, 5, b[x] ^= a[x + y];))
    FOR5(x, 1, FOR5(y, 5, a[y + x] ^= b[(x + 4) % 5] ^ rol(b[(x + 1) % 5], 1);))
    // Rho and pi
    t = a[1];
    x = 0;
    REPEAT24(b[0] = a[pi[x]]; a[pi[x]] = rol(t, rho[x]); t = b[0]; x++;)
    // Chi
    FOR5(y, 5,
         FOR5(x, 1, b[x] = a[y + x];) FOR5(
             x, 1, a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);))
    // Iota
    a[0] ^= RC[i];
  }
}

/** Sponge helpers. **/

static inline void _xorinto(uint8_t* dst, const uint8_t* src, size_t len) {
  for (size_t i = 0; i < len; i += 1) {
    dst[i] ^= src[i];
  }
}

static inline void _sponge_squeeze(keccak_sponge* const restrict sponge,
                                   uint8_t* restrict out,
                                   const size_t len) {
  size_t remaining = len;
  while (remaining) {
    size_t cando = sponge_rate - sponge->position;
    uint8_t* state = ((uint8_t*)sponge->a) + sponge->position;
    if (cando > remaining) {
      memcpy(out, state, remaining);
      sponge->position += remaining;
      remaining = 0;
    } else {
      memcpy(out, state, cando);
      keccakf(sponge->a);
      sponge->position = 0;
      remaining -= cando;
      out += cando;
    }
  }
}

static inline void _sponge_absorb(keccak_sponge* const restrict sponge,
                                  const uint8_t* restrict in,
                                  const size_t len) {
  size_t remaining = len;
  while (remaining) {
    size_t cando = sponge_rate - sponge->position;
    uint8_t* state = ((uint8_t*)sponge->a) + sponge->position;
    if (cando > remaining) {
      _xorinto(state, in, remaining);
      sponge->position += remaining;
      remaining = 0;
    } else {
      _xorinto(state, in, cando);
      keccakf(sponge->a);
      sponge->position = 0;
      remaining -= cando;
      in += cando;
    }
  }
}

static inline void _shake_pad(keccak_sponge* const restrict sponge,
                              const uint8_t ds) {
  uint8_t* state = ((uint8_t*)sponge->a);
  /* little-endian *bit* ordering   2^ 01234567 */
  state[sponge->position] ^= ds;  /* 11111000 */
  state[sponge_rate - 1] ^= 0x80; /* 00000001 */
  keccakf(sponge->a);
  sponge->position = 0;
}

/** SHAKE256 **/

#define FLAG_ABSORBING UINT64_C(0x53efb6b64647b401)
#define FLAG_SQUEEZING UINT64_C(0x44a50aed67ba8c04)
#define DS_SHAKE 0x1f
#define DS_MACKEY 0x3f

int shake256_init(keccak_sponge* const restrict sponge) {
  if (sponge == NULL) {
    return SPONGERR_NULL;
  };
  memset(sponge->a, 0, 200);
  sponge->position = 0;
  sponge->flags = FLAG_ABSORBING;
  return 0;
}

int shake256_absorb(keccak_sponge* const restrict sponge,
                    const uint8_t* const restrict in,
                    const size_t inlen) {
  int err = 0;
  if (sponge == NULL) {
    return SPONGERR_NULL;
  }
  if (in == NULL) {
    return SPONGERR_NULL;
  }
  if (inlen > (SIZE_MAX >> 1)) {
    return SPONGERR_RSIZE;
  }
  if (sponge->position >= sponge_rate) {
    return SPONGERR_INVARIANT;
  }
  switch (sponge->flags) {
    case (FLAG_SQUEEZING):
      // The sponge has already been finalized by applying padding.
      return 2;
    case (FLAG_ABSORBING):
      break;
    default:
      // The sponge hasn't been initialized.
      return 1;
  }

  _sponge_absorb(sponge, &in[sponge->position], inlen);

  return err;
}

int shake256_squeeze(keccak_sponge* const restrict sponge,
                     uint8_t* const restrict out,
                     const size_t outlen) {
  if (sponge == NULL) {
    return SPONGERR_NULL;
  }
  if (out == NULL) {
    return SPONGERR_NULL;
  }
  if (outlen > (SIZE_MAX >> 1)) {
    return SPONGERR_RSIZE;
  }
  if (sponge->position >= sponge_rate) {
    return SPONGERR_INVARIANT;
  }

  switch (sponge->flags) {
    case (FLAG_SQUEEZING):
      break;
    case (FLAG_ABSORBING):
      // If we're still absorbing, pad the message and apply Keccak-f.
      _shake_pad(sponge, DS_SHAKE);
      sponge->flags = FLAG_SQUEEZING;
      break;
    default:
      // The sponge hasn't been initialized.
      return SPONGERR_NOTINIT;
  }

  _sponge_squeeze(sponge, out, outlen);

  return 0;
}


int shake256_squeezemax(keccak_sponge* sponge,
                        uint8_t* const restrict out,
                        const size_t outlen,
                        const uint8_t max) {
  if (sponge == NULL) {
    return SPONGERR_NULL;
  }
  if (out == NULL) {
    return SPONGERR_NULL;
  }
  if (outlen > (SIZE_MAX >> 1)) {
    return SPONGERR_RSIZE;
  }
  if (sponge->position >= sponge_rate) {
    return SPONGERR_INVARIANT;
  }
  uint8_t buf[1] = {0};
  while (outlen) {
    do {
      shake256_squeeze(sponge, out, 1);
    } while (!(*out < max));
    outlen--, out++;
  }
}

int shake256(uint8_t* const restrict out,
             const size_t outlen,
             const uint8_t* const restrict in,
             const size_t inlen) {
  int err = 0;
  keccak_sponge sponge;
  err = shake256_init(&sponge);
  if (err != 0) {
    return err;
  }
  err = shake256_absorb(&sponge, in, inlen);
  if (err != 0) {
    return err;
  }
  err = shake256_squeeze(&sponge, out, outlen);
  memset_s(&sponge, sizeof(keccak_sponge), 0, sizeof(keccak_sponge));
  return err;
}

int mac_init(keccak_sponge* const restrict sponge,
             const uint8_t* const key,
             const size_t keylen) {
  int err = 0;
  err = shake256_init(sponge);
  if (err != 0) {
    return err;
  }
  err = shake256_absorb(sponge, key, keylen);
  if (err != 0) {
    return err;
  }
  _shake_pad(sponge, DS_MACKEY);
  return err;
}

int mac_cached(keccak_sponge* const restrict sponge,
               const uint8_t* const state) {
  int err = 0;
  err = shake256_init(sponge);
  if (err != 0) {
    return err;
  }
  memcpy(sponge->a, state, 200);
  return err;
}

int mac_cache_key(uint64_t* const state,
                  const uint8_t* const key,
                  const size_t keylen) {
  int err = 0;
  keccak_sponge sponge;
  err = shake256_init(&sponge);
  if (err != 0) {
    return err;
  }
  err = shake256_absorb(&sponge, key, keylen);
  if (err != 0) {
    return err;
  }
  _shake_pad(&sponge, DS_MACKEY);
  memcpy(state, &sponge.a, 200);
  memset_s(&sponge, sizeof(keccak_sponge), 0, sizeof(keccak_sponge));
  return err;
}
