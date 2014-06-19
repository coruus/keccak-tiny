/* Like the Keccak Team's compact implementation of Keccak, but even
 * smaller. And fully unrolled using macro magic.
 *
 * Implemented by: David Leon Gil
 * License: CC0
 */
#include "keccak.h"
#include "u.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))

#define R6(e) e e e e e e
#define R24(e) R6(e e e e)
#define R5(e) e e e e e
#define L5(v, s, e) \
  v = 0;            \
  R5(e; v += s;)

void keccakf(void* state) {
  uint64_t* a = (uint64_t*)state;
  uint64_t b[5] = {0};
  uint64_t t = 0;
  uint8_t x, y, i = 0;

  R24(
      // Theta
      L5(x, 1, b[x] = 0; L5(y, 5, b[x] ^= a[x + y];))
      L5(x, 1, L5(y, 5, a[y + x] ^= b[(x + 4) % 5] ^ rol(b[(x + 1) % 5], 1);))
      // Rho and pi
      t = a[1];
      x = 0;
      R24(b[0] = a[pi[x]]; a[pi[x]] = rol(t, rho[x]); t = b[0]; x++;)
      // Chi
      L5(y,
         5,
         L5(x, 1, b[x] = a[y + x];)
         L5(x, 1, a[y + x] = b[x] ^ ~b[(x + 1) % 5] & b[(x + 2) % 5];))
      // Iota
      a[0] ^= RC[i];
      i++;)
}
