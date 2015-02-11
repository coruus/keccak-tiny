#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* The internal, non-opaque definition of the sponge struct. */
typedef struct sponge_internal {
  uint64_t a[25];    // the sponge state
  uint64_t _[1];     // 8 bytes of padding (or space for the rate)
  uint64_t flags;    // the hash object's status
  uint64_t position; // the position into the sponge
} keccak_sponge;

#define _KECCAK_SPONGE_INTERNAL
#include "shake256.h"

/* For sucky compilers that don't support this lovely C11 feature
 * (all of them, today): */
#define static_assert(STMT)
/* For future compilers that do: */
static_assert(sizeof(keccak_sponge_opaque) >= sizeof(keccak_sponge));
static_assert(alignof(keccak_sponge_opaque) >= alignof(keccak_sponge));

/*** The Keccak-f[1600] permutation ***/

/** Constants. **/
static const uint8_t rho[24] = \
  { 1,  3,   6, 10, 15, 21,
    28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43,
    62, 18, 39, 61, 20, 44};
static const uint8_t pi[24] = \
  {10,  7, 11, 17, 18, 3,
    5, 16,  8, 21, 24, 4,
   15, 23, 19, 13, 12, 2,
   20, 14, 22,  9, 6,  1};
static const uint64_t RC[24] = \
  {1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
   0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
   0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
   0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
   0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
   0x800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
   0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};

/** Keccak-f[1600] **/

/* Helper macros to unroll the permutation. */
#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))
#define REPEAT6(e) e e e e e e
#define REPEAT24(e) REPEAT6(e e e e)
#define REPEAT5(e) e e e e e
#define FOR5(v, s, e) v = 0; REPEAT5(e; v += s;)

static inline void keccakf(void* state) {
  uint64_t* a = (uint64_t*)state;
  uint64_t b[5] = {0};
  uint64_t t = 0;
  uint8_t x, y;

  for (int i = 0; i < 24; i++) {
    // Theta
    FOR5(x, 1,
         b[x] = 0;
         FOR5(y, 5,
              b[x] ^= a[x + y]; ))
    FOR5(x, 1,
         FOR5(y, 5,
              a[y + x] ^= b[(x + 4) % 5] ^ rol(b[(x + 1) % 5], 1); ))
    // Rho and pi
    t = a[1];
    x = 0;
    REPEAT24(b[0] = a[pi[x]];
             a[pi[x]] = rol(t, rho[x]);
             t = b[0];
             x++; )
    // Chi
    FOR5(y,
       5,
       FOR5(x, 1,
            b[x] = a[y + x];)
       FOR5(x, 1,
            a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]); ))
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
    size_t dolen;
    if (cando > len) {
      dolen = len;
      memcpy(out, state, dolen);
      sponge->position += dolen;
    } else {
      dolen = cando;
      memcpy(out, state, dolen);
      keccakf(sponge->a);
      sponge->position = 0;
    }
    remaining -= dolen;
    out += dolen;
  }
}

static inline void _sponge_absorb(keccak_sponge* const restrict sponge,
                                  const uint8_t* restrict in,
                                  const size_t len) {
  size_t remaining = len;
  while (remaining) {
    size_t cando = sponge_rate - sponge->position;
    uint8_t* state = ((uint8_t*)sponge->a) + sponge->position;
    size_t dolen;
    if (cando > len) {
      dolen = len;
      _xorinto(state, in, dolen);
      sponge->position += dolen;
    } else {
      dolen = cando;
      _xorinto(state, in, dolen);
      keccakf(sponge->a);
      sponge->position = 0;
    }
    remaining -= dolen;
    in += dolen;
  }
}

/** Xor in the MBR padding and domain-separator byte, then apply Keccak-f.
 *
 * @param sponge[in,out]
 */
static inline void _shake_pad(keccak_sponge* const restrict sponge) {
  uint8_t* state = ((uint8_t*)sponge->a);
  /* little-endian *bit* ordering   2^ 01234567 */
  state[sponge->position] ^= 0x1f;  /* 11111000 */
  state[sponge_rate - 1]  ^= 0x80;  /* 00000001 */
  keccakf(sponge->a);
  sponge->position = 0;
}

/** "Forget" the previous state of the sponge by overwriting len bytes of
 * the state with zeros, applying the permutation as necessary. The generic
 * difficulty of recovering the state is 2^(8*len). (And thus len should
 * generally be equal to the security strength of the sponge instance.)
 *
 * @param sponge[in,out]
 * @param len             The number of bytes of state to forget.
 */
static inline void _sponge_forget(keccak_sponge* const restrict sponge,
                                  const size_t len) {
  size_t remaining = len;
  while (remaining) {
    size_t done;
    do {
      size_t cando = sponge_rate - sponge->position;
      uint8_t* state = ((uint8_t*)sponge->a) + sponge->position;
      size_t dolen;
      if (cando > len) {
        dolen = len;
        memset(state, 0, dolen);
        sponge->position += dolen;
      } else {
        dolen = cando;
        memset(state, 0, dolen);
        keccakf(sponge->a);
        sponge->position = 0;
      }
      done = dolen;
    } while (0);
    remaining -= done;
  }
}

/** SHAKE256 **/

#define FLAG_ABSORBING   UINT64_C(0x53efb6b64647b401)
#define FLAG_SQUEEZING   UINT64_C(0x44a50aed67ba8c04)
#define FLAG_SPONGEPRG   UINT64_C(0xbf0420879da9f2d9)

/** Initialize a SHAKE instance.
 *
 * @param sponge[out] Pointer to sponge to initialize.
 * @return 0 on success; -1 if the pointer is NULL.
 */
int shake256_init(keccak_sponge* const restrict sponge) {
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

/** Squeeze output from the sponge.
 *
 * @param  sponge[in,out]  Pointer to sponge.
 * @param  out[out]        Buffer to write squeezed output into.
 * @param  outlen[in]      Length of output to squeeze.
 * @return 0 on success, < 0 if a pointer is NULL, > 0 if the
 *         sponge has not yet been initialized.
 */
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
      _shake_pad(sponge);
      sponge->flags = FLAG_SQUEEZING;
      break;
    default:
      // The sponge hasn't been initialized.
      return SPONGERR_NOTINIT;
  }

  _sponge_squeeze(sponge, out, outlen);

  return 0;
}

/** Initialize a SpongePRG with some entropy. Immediately calls sprng_forget
 * to prevent backtracking to the entropy. NOTE: The input buffer is zeroized.
 *
 * @param   sponge[in,out]   Pointer to sponge.
 * @param   entropy[in,out]  Buffer with initial entropy; zeroized on success.
 * @param   entropylen[in]   Length of the initial entropy input.
 * @return  0 on success, < 0 if a pointer is NULL, > 0 if the
 *          sponge's state is invalid.
 */
int sprng256_init(keccak_sponge* const restrict sponge,
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

  int err = sprng256_forget(sponge);            // Forget to prevent baktracking.
  return err;
}

/** "Forget" the current state of the SPRNG, to prevent backtracking
 * to the input entropy.
 *
 * @param  sponge[in,out]  Pointer to sponge.
 * @return 0 on success, < 0 if a pointer is NULL, > 0 if the
 *         sponge's state is invalid.
 */
int sprng256_forget(keccak_sponge* const restrict sponge) {
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
  _shake_pad(sponge);
  if (sponge->position == 0) {
    // The permutation was applied because of the padding rule.
    return 0;
  }

  // The permutation has not yet been applied, so apply it.
  keccakf(sponge->a);
  sponge->position = 0;

  return 0;
}


/** SpongePRG next operation: Absorb entropy, forget, and zeroize input buffer.
 *
 * @param   sponge[in,out]   Pointer to sponge.
 * @param   entropy[in,out]  Buffer with entropy; zeroized on success.
 * @param   entropylen[in]   Length of the entropy input.
 * @return  0 on success, < 0 if a pointer is NULL, > 0 if the
 *          sponge's state is invalid.
 */
int sprng256_next(keccak_sponge* const restrict sponge,
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

  int err = sprng256_forget(sponge);  // And prevent baktracking.

  return err;
}

/** SpongePRG squeeze operation: Output entropy without calling forget.
 * This means that the output can be backtracked from the sponge state.
 * Use sprng_random unless you know that you want this (and, e.g., will
 * follow several calls to this with a call to forget).
 *
 * @param   sponge[in,out]   Pointer to sponge.
 * @param   out[out]         Output buffer.
 * @param   outlen[in]       Length of the output.
 * @return  0 on success, < 0 if a pointer is NULL, > 0 if the
 *          sponge's state is invalid.
 */
int sprng256_squeeze(keccak_sponge* const restrict sponge,
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

/** SpongePRG random: Squeeze and forget.
 *
 * @param   sponge[in,out]   Pointer to sponge.
 * @param   out[out]         Output buffer.
 * @param   outlen[in]       Length of the output.
 * @return  0 on success, < 0 if a pointer is NULL, > 0 if the
 *          sponge's state is invalid.
 */
int sprng256_random(keccak_sponge* const restrict sponge,
                    uint8_t* const restrict out,
                    const size_t outlen) {
  int err = sprng256_squeeze(sponge, out, outlen);
  if (err != 0) {
    return err;
  }
  err = sprng256_forget(sponge);
  return err;
}
