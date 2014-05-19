/* Like the Keccak Team's compact implementation of Keccak, but even
 * smaller.
 *
 * Implemented by: David Leon Gil
 * License: CC0
 */
#include "k.h"
#include "u.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define rol(x, s) (((x) << s) | ((x) >> (64-s)))
#define mod5(i) ((i)%5)

#define R6(e) e e e e e e
#define R24(e) R6(e e e e)

SIV keccakr(uint64_t* const restrict state,
            const uint64_t rc) {
  uint64_t BC[5] = {0};
  uint64_t t = 0;
  uint8_t x, y;

  // Theta
  for (x = 0; x < 5; x++) {
    BC[x] = 0;
    for (y = 0; y < 25; y += 5) {
      BC[x] ^= state[x + y];
    }
  }
  for (x = 0; x < 5; x++) {
    t = BC[mod5(x + 4)] ^ rol(BC[mod5(x + 1)], 1);
    for (y = 0; y < 25; y += 5) {
      state[y + x] ^= t;
    }
  }

  // Rho and pi
  t = state[1];
  for (x = 0; x < 24; x++) {
    BC[0] = state[pi[x]];
    state[pi[x]] = rol(t, rho[x]);
    t = BC[0];
  }

  // Chi
  for (y = 0; y < 25; y += 5) {
    for (x = 0; x < 5; x++) {
      BC[x] = state[y + x];
    }
    for (x = 0; x < 5; x++) {
      state[y + x] = BC[x] ^ ((~BC[mod5(x + 1)]) & BC[mod5(x + 2)]);
    }
  }

  // Iota
  state[0] ^= rc;
}

void keccakf(void* const state) {
  //FOR(i, 1, 24, keccakr((uint64_t*)state, RC[i]));
  int i = 0; R24(keccakr((uint64_t*)state, RC[i]); i++; )
}
