#include "keccak.h"
#include "fips202.h"

#include <stdint.h>
#include <stdlib.h>

#define _(S) do { S } while (0)

#define FOR(i, ST, L, S) \
  _(for (size_t i = 0; i < L; i += ST) { S; })

#define mkapply_ds(NAME, S)                                          \
  static inline void NAME(uint8_t* dst,                              \
                          const uint8_t* src,                        \
                          size_t len) {                              \
    FOR(i, 1, len, S);                                               \
  }
#define mkapply_sd(NAME, S)                                          \
  static inline void NAME(const uint8_t* src,                        \
                          uint8_t* dst,                              \
                          size_t len) {                              \
    FOR(i, 1, len, S);                                               \
  }

#define P keccakf
#define Plen 200

// Fold P*F over the full blocks of an input.
#define foldP(I, L, F) \
  while (L >= rate) {  \
    F(a, I, rate);     \
    P(a);              \
    I += rate;         \
    L -= rate;         \
  }

mkapply_ds(xorin, dst[i] ^= src[i])  // xorin
mkapply_sd(setout, dst[i] = src[i])  // setout

static inline void clear(uint8_t* a) {
  FOR(i, 1, 200, a[i] = 0);
}

static inline int hash(uint8_t* out, size_t outlen,
                       const uint8_t* in, size_t inlen,
                       size_t rate, uint8_t delim) {
  if ((out == NULL) || ((in == NULL) && inlen != 0) || (rate >= Plen)) {
    return -1;
  }
  uint8_t a[Plen] = {0};
  // Absorb input.
  foldP(in, inlen, xorin);
  // Xor in the DS and pad frame.
  a[inlen] ^= delim;
  a[rate - 1] ^= 0x80;
  // Xor in the last block.
  xorin(a, in, inlen);
  // Apply P
  P(a);
  // Squeeze output.
  foldP(out, outlen, setout);
  setout(a, out, outlen);
  clear(a);
  return 0;
}

#define defshake(bits)                                            \
  int shake##bits(uint8_t* out, size_t outlen,                    \
                  const uint8_t* in, size_t inlen) {             \
    return hash(out, outlen, in, inlen, 200 - (bits / 4), 0x1f);  \
  }


#define defsha3(bits)                                             \
  int sha3_##bits(uint8_t* out, size_t outlen,                    \
                  const uint8_t* in, size_t inlen) {              \
    if (outlen > (bits/8)) {                                      \
      return -1;                                                  \
    }                                                             \
    return hash(out, outlen, in, inlen, 200 - (bits / 4), 0x06);  \
  }

/* FIPS202 SHAKE VOFs */
defshake(128) //
defshake(256) //
/* FIPS202 SHA3 FOFs */
defsha3(224) //
defsha3(256) //
defsha3(384) //
defsha3(512) //
