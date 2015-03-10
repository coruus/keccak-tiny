#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* The internal, non-opaque definition of the sponge struct. */
typedef struct sponge_internal {
  uint64_t a[25];     // the sponge state
  uint64_t _[1];      // 8 bytes of padding (or space for the rate)
  uint64_t flags;     // the hash object's status
  uint64_t position;  // the position into the sponge
} keccak_sponge;

#define _KECCAK_SPONGE_INTERNAL
#include "shake.h"

/* For future compilers that support it: */
// static_assert(sizeof(keccak_sponge_opaque) >= sizeof(keccak_sponge));
// static_assert(alignof(keccak_sponge_opaque) >= alignof(keccak_sponge));

/*** The Keccak-f[1600] permutation ***/

/** Constants. **/
static const uint8_t rho[24] = {1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
                                27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};
static const uint8_t pi[24] = {10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                               15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1};
#define RC_B(x, n) ((((x##ull) >> n) & 1) << ((1 << n) - 1))
#define RC_X(x)                                                                  \
  (RC_B(x, 0) | RC_B(x, 1) | RC_B(x, 2) | RC_B(x, 3) | RC_B(x, 4) | RC_B(x, 5) | \
   RC_B(x, 6))
static const uint64_t RC[24] = {
    RC_X(0x01), RC_X(0x1a), RC_X(0x5e), RC_X(0x70), RC_X(0x1f), RC_X(0x21),
    RC_X(0x79), RC_X(0x55), RC_X(0x0e), RC_X(0x0c), RC_X(0x35), RC_X(0x26),
    RC_X(0x3f), RC_X(0x4f), RC_X(0x5d), RC_X(0x53), RC_X(0x52), RC_X(0x48),
    RC_X(0x16), RC_X(0x66), RC_X(0x79), RC_X(0x58), RC_X(0x21), RC_X(0x74)};

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
    FOR5(y, 5, FOR5(x, 1, b[x] = a[y + x];)
                   FOR5(x, 1, a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);))
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

static inline void _sponge_pad(keccak_sponge* const restrict sponge,
    uint8_t ds) {
  uint8_t* state = ((uint8_t*)sponge->a);
  /* little-endian *bit* ordering   2^ 01234567 */
  state[sponge->position] ^= ds; /* 11111000 */
  state[sponge_rate - 1]  ^= 0x80;  /* 00000001 */
  keccakf(sponge->a);
  sponge->position = 0;
}

static inline void _sponge_forget(keccak_sponge* const restrict sponge,
                                  const size_t len) {
  size_t remaining = len;
  while (remaining) {
    size_t cando = sponge_rate - sponge->position;
    uint8_t* state = ((uint8_t*)sponge->a) + sponge->position;
    if (cando > remaining) {
      memset(state, 0, remaining);
      sponge->position += remaining;
      remaining = 0;
    } else {
      memset(state, 0, cando);
      keccakf(sponge->a);
      sponge->position = 0;
      remaining -= cando;
    }
  }
}

/** SHAKE **/

#define FLAG_ABSORBING UINT64_C(0x53efb6b64647b401)
#define FLAG_SQUEEZING UINT64_C(0x44a50aed67ba8c04)
#define FLAG_SPONGEPRG UINT64_C(0xbf0420879da9f2d9)

#define DS_SHAKE 0x1f

/** Initialize a SHAKE instance.
 *
 * @param sponge[out] Pointer to sponge to initialize.
 * @return 0 on success; -1 if the pointer is NULL.
 */
int shake_init(keccak_sponge* const restrict sponge) {
  if (sponge == NULL) {
    return SPONGERR_NULL;
  };
  memset(sponge->a, 0, 200);
  sponge->position = 0;
  sponge->flags = FLAG_ABSORBING;
  return 0;
}

/** Absorb more data into the sponge.
 *
 * @param  sponge[in,out]  Pointer to sponge.
 * @param  in[in]          Input to absorb.
 * @param  inlen[in]       Length of the input.
 * @return 0 on success, < 0 if a pointer is NULL, > 0 if the
 *         sponge has already been finalized, or has not yet
 *         been initialized.
 */
int shake_absorb(keccak_sponge* const restrict sponge,
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

int shake_pad(keccak_sponge* const restrict sponge,
                 const uint8_t ds) {
  int err = 0;
  if (sponge == NULL) {
    return SPONGERR_NULL;
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

  _sponge_pad(sponge, ds);

  return err;
}

int shake_squeeze(keccak_sponge* const restrict sponge,
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
      _sponge_pad(sponge, DS_SHAKE);
      sponge->flags = FLAG_SQUEEZING;
      break;
    default:
      // The sponge hasn't been initialized.
      return SPONGERR_NOTINIT;
  }

  _sponge_squeeze(sponge, out, outlen);

  return 0;
}

int shake(uint8_t* const restrict out,
          const size_t outlen,
          const uint8_t* const restrict in,
          const size_t inlen) {
  int err = 0;
  keccak_sponge sponge;
  err = shake_init(&sponge);
  if (err != 0) {
    return err;
  }
  err = shake_absorb(&sponge, in, inlen);
  if (err != 0) {
    return err;
  }
  err = shake_squeeze(&sponge, out, outlen);
  memset(&sponge, 0, sizeof(keccak_sponge));
  return err;
}

int sprng_init(keccak_sponge* const restrict sponge,
               uint8_t* const entropy,
               const size_t entropylen) {
  if (sponge == NULL) {
    return SPONGERR_NULL;
  }
  if (entropy == NULL) {
    return SPONGERR_NULL;
  }
  if (entropylen > (SIZE_MAX >> 1)) {
    return SPONGERR_RSIZE;
  }

  memset(sponge, 0, sizeof(keccak_sponge));     // Initialize the sponge struct,
  sponge->flags = FLAG_SPONGEPRG;               // and the flags,
  _sponge_absorb(sponge, entropy, entropylen);  // absorb the entropy into the state,
  memset(entropy, 0, entropylen);               // and zeroize the input buffer.

  int err = sprng_forget(sponge);  // Forget to prevent baktracking.
  return err;
}

int sprng_forget(keccak_sponge* const restrict sponge) {
  if (sponge == NULL) {
    return SPONGERR_NULL;
  }
  if (sponge->position >= sponge_rate) {
    return SPONGERR_INVARIANT;
  }
  if (sponge->flags != FLAG_SPONGEPRG) {
    return SPONGERR_NOTINIT;
  }

  // Apply the permutation; we then are at position zero.
  keccakf(sponge->a);
  sponge->position = 0;

  // Write sponge_security_strength zero bytes. In this case,
  // this is equivalent to:
  //    memset(sponge->a, 0, 32);
  //    sponge->position = 32;
  _sponge_forget(sponge, sponge_security_strength);

  // Apply padding.
  _sponge_pad(sponge, DS_SHAKE);
  if (sponge->position == 0) {
    // The permutation was applied because of the padding rule.
    return 0;
  }

  // The permutation has not yet been applied, so apply it.
  keccakf(sponge->a);
  sponge->position = 0;

  return 0;
}

int sprng_next(keccak_sponge* const restrict sponge,
               uint8_t* const entropy,
               const size_t entropylen) {
  if (sponge == NULL) {
    return SPONGERR_NULL;
  }
  if (entropy == NULL) {
    return SPONGERR_NULL;
  }
  if (entropylen > (SIZE_MAX >> 1)) {
    return SPONGERR_RSIZE;
  }
  if (sponge->flags != FLAG_SPONGEPRG) {
    return SPONGERR_NOTINIT;
  }

  _sponge_absorb(sponge, entropy, entropylen);  // Absorb the entropy,
  memset(entropy, 0, entropylen);               // zeroize the buffer,

  int err = sprng_forget(sponge);  // And prevent baktracking.

  return err;
}

int sprng_squeeze(keccak_sponge* const restrict sponge,
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
  if (sponge->flags != FLAG_SPONGEPRG) {
    // The SpongePRG hasn't been initialized.
    return SPONGERR_NOTINIT;
  }
  _sponge_squeeze(sponge, out, outlen);
  return 0;
}

int sprng_random(keccak_sponge* const restrict sponge,
                 uint8_t* const restrict out,
                 const size_t outlen) {
  int err = sprng_squeeze(sponge, out, outlen);
  if (err != 0) {
    return err;
  }
  err = sprng_forget(sponge);
  return err;
}
