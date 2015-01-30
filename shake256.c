#include <stdint.h>
#include <stdlib.h>
#include <string.h>



/*******************************************************************************
 * Helper macros.
 */
#ifndef UINT64_C
// TODO(dlg): SC?
#define UINT64_C(VAL) (VAL##ULL)
#endif

#ifndef SIZE_C
#define SIZE_C(VAL) ((size_t)(VAL##ULL))
#endif

// Errors.
#define SPONGERR_NULL      -1  /* a passed pointer was NULL             */
#define SPONGERR_RSIZE     -2  /* the passed length is > RSIZE_MAX      */
#define SPONGERR_INVARIANT  1  /* the sponge invariant was violated     */
#define SPONGERR_NOTINIT    2  /* the sponge isn't initalized           */
#define SPONGERR_FINALIZED  3  /* the sponge has already been finalized */

// Wrap blocks.
#define _(S) do { S } while (0)

// Checks for errors.
#define checkinv(SPONGE) \
  _(if (sponge->position >= sponge_rate) { return SPONGERR_INVARIANT; })
#define checknull(PTR) _(if (PTR == NULL) { return SPONGERR_NULL; })
#define checkrsize(LEN) _(if ((size_t)LEN > (SIZE_MAX >> 1)) { return SPONGERR_RSIZE; })

#define mkapply_ds(NAME, S)                                               \
  static inline void NAME(uint8_t* dst, const uint8_t* src, size_t len) { \
    for (size_t i = 0; i < len; i += 1) { S; }                            \
  }

/** Xor len bytes from src into dst.
 *
 * @param dst[in,out]
 * @param src[in]
 * @param len
 */
mkapply_ds(_xorinto, dst[i] ^= src[i])  //




/*******************************************************************************
 * The Keccak-f[1600] permutation
 */

/*** Constants. ***/
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
   0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
   0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
   0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};



/*******************************************************************************
 * Keccak-f[1600]
 */

/*** Helper macros to unroll the permutation. ***/
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

/*******************************************************************************
 * The sponge construction.
 */

/* The sponge structure.
 * 
 * X-well alignment, to avoid 4KiB aliasing:
 *        224 %  32 ==  0
 *   but 4096 % 224 == 64
 */
typedef struct sponge {
  uint64_t a[25];    // the sponge state
  uint64_t _[1];     // 8 byts of padding
  uint64_t flags;    // the hash object's status
  uint64_t position; // the position into the sponge
} keccak_sponge;


// Flags indicating sponge state.
#define hash_absorbing UINT64_C(0x53efb6b64647b401)
#define hash_squeezing UINT64_C(0x44a50aed67ba8c04)

// Lengths.
#define sponge_bytelen           SIZE_C(200)
/* sponge_rate == sponge_bytelen - sponge_capacity */
#define sponge_rate              SIZE_C(136)
/* sponge_security_strength == capacity / 2 == 32B == 256b */
#define sponge_security_strength SIZE_C(32) 





#define SPONGEDO(STMT)                                         \
  size_t done;                                                 \
  do {                                                         \
    size_t cando = sponge_rate - sponge->position;             \
    uint8_t* state = ((uint8_t*)sponge->a) + sponge->position; \
    size_t dolen;                                              \
                                                               \
    if (cando > len) {                                         \
      dolen = len;                                             \
      STMT;                                                    \
      sponge->position += dolen;                               \
    } else {                                                   \
      dolen = cando;                                           \
      STMT;                                                    \
      keccakf(sponge->a);                                      \
      sponge->position = 0;                                    \
    }                                                          \
    done = dolen;                                              \
  } while (0)


#define SPONGEOP(NAME, CONST, PARAM, STMT)                                         \
  static inline void NAME(keccak_sponge* const restrict sponge,                    \
                          CONST uint8_t* restrict PARAM, const size_t len) {       \
    size_t remaining = len;                                                        \
    while (remaining) {                                                            \
      SPONGEDO(STMT);                                                              \
      remaining -= done;                                                           \
      PARAM += done;                                                               \
    }                                                                              \
  }

SPONGEOP(_sponge_squeeze, , out, memcpy(out, state, dolen))     //
SPONGEOP(_sponge_absorb, const, in, _xorinto(state, in, dolen)) //

/** Xor in the MBR padding and domain-separator byte, then apply Keccak-f.
 *
 * @param sponge[in,out]
 */
static inline void _shake_pad(keccak_sponge* const restrict sponge) {
  uint8_t* state = ((uint8_t*)sponge->a);
  // little-endian *bit* ordering   2^ 01234567
  state[sponge->position] ^= 0x1f;  // 11111000
  state[sponge_rate - 1]  ^= 0x80;  // 00000001
  keccakf(sponge->a);
  sponge->position = 0;
}

static inline void _sponge_forget(keccak_sponge* const restrict sponge, const size_t len) {
  size_t remaining = len;
  while (remaining) {
    SPONGEDO(memset(state, 0, dolen)); 
    remaining -= done;
  }
}

/*******************************************************************************
 * SHAKE256
 */

/** Initialize a SHAKE256 sponge.
 *
 * @param sponge[out] Pointer to sponge to initialize.
 * @return 0 on success; -1 if the pointer is NULL.
 */
int shake256_init(keccak_sponge* const restrict sponge) {
  checknull(sponge);
  sponge->position = 0;
  memset(sponge->a, 0, 200);
  sponge->flags = hash_absorbing;
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
  checknull(sponge);
  checknull(in);
  checkrsize(inlen);
  checkinv(sponge);
  switch (sponge->flags) {
    case (hash_squeezing):
      // The sponge has already been finalized by applying padding.
      return 2;
    case (hash_absorbing):
      break;
    default:
      // The sponge hasn't been initialized.
      return 1;
  }

  size_t remaining = inlen;
  size_t pos = 0;
  _sponge_absorb(sponge, &in[pos], remaining);

  return err;
}

/** Absorb more data into the sponge.
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
  checknull(sponge);
  checknull(out);
  checkrsize(outlen);
  checkinv(sponge);

  switch (sponge->flags) {
    case (hash_squeezing):
      break; 
    case (hash_absorbing):
      // If we're still absorbing, pad the message and apply Keccak-f.
      _shake_pad(sponge);
      sponge->flags = hash_squeezing;
      break;
    default:
      // The sponge hasn't been initialized.
      return SPONGERR_NOTINIT;
  }
  
  _sponge_squeeze(sponge, out, outlen);
  
  return 0;
}

/** "Forget" the previous state of the sponge by overwriting
 * security_strength bytes of the state with zeros.
 *
 * @param  sponge[in,out]  Pointer to sponge.
 * @return 0 on success, < 0 if a pointer is NULL, > 0 if the
 *         sponge has not yet been initialized.
 */
int spongerng_forget(keccak_sponge* const restrict sponge) {
  checknull(sponge);
  checkinv(sponge);

  switch (sponge->flags) {
    case (hash_squeezing):
      break;
    case (hash_absorbing):
      // If we're still absorbing, pad the message and apply Keccak-f.
      _shake_pad(sponge);
      sponge->flags = hash_squeezing;
      break;
    default:
      // The sponge hasn't been initialized.
      return SPONGERR_NOTINIT;
  }
 
  // Write 32 zero bytes.
  _sponge_forget(sponge, sponge_security_strength);
  // Apply padding.
  _shake_pad(sponge);
  sponge->flags = hash_absorbing;
  
  return 0;
}

#define spongerng_init shake256_init
#define spongerng_read shake256_squeeze

int spongerng_next(keccak_sponge* const restrict sponge,
                   const uint8_t* const entropy,
                   const size_t entropylen) {
  int err = 0;
  // QQQQ: Is it better to absorb first?
  err = spongerng_forget(sponge);
  if (err != 0) { 
    return err;
  }
  err = shake256_absorb(sponge, entropy, entropylen);
  if (err != 0) {
    return err;
  }
  return 0;
}
