/* Like the Keccak Team's compact implementation of Keccak, but even
 * smaller. And fully unrolled using macro magic.
 *
 * Implemented by: David Leon Gil
 * License:        CC0
 */
#include "keccak.h"
#include "fips202.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

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

/**** The Keccak-f[1600] permutation ****/

#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))

#define REPEAT6(e) e e e e e e
#define REPEAT24(e) REPEAT6(e e e e)
#define REPEAT5(e) e e e e e
#define FOR5(v, s, e) \
  v = 0;            \
  REPEAT5(e; v += s;)

void keccakf(void* state) {
  uint64_t* a = (uint64_t*)state;
  uint64_t b[5] = {0};
  uint64_t t = 0;
  uint8_t x, y, i = 0;

  REPEAT24(
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
              a[y + x] = b[x] ^ ~b[(x + 1) % 5] & b[(x + 2) % 5]; ))
      // Iota
      a[0] ^= RC[i];
      i++; )
}
