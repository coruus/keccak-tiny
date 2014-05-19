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
#include <stdio.h>

#define rol(x, s) (((x) << s) | ((x) >> (64-s)))

#define R6(e) e e e e e e
#define R24(e) R6(e e e e)
#define R5(e) e e e e e
//static const uint8_t C[24] = "#,PZ13[O(&?8AIOMLB0X[J3^";

void keccakf(void* state) {
  uint64_t* a = (uint64_t*)state;
  uint64_t b[5] = {0};
  uint64_t c, t = 0;
  uint8_t x, y, i = 0;

  R24(
  // Theta
  R5(b[x]=0; y=0;
     R5(b[x]^= a[x+y]; y+=5;)
     x++;)
  x=0;
  R5(t = b[(x+4)%5] ^ rol(b[(x+1)%5], 1);
     y=0; R5(a[y+x]^=t; y+=5;) x++;
    )
  // Rho and pi
  t = a[1];
  x = 0;
  R24(b[0] = a[pi[x]];
      a[pi[x]] = rol(t, rho[x]);
      t = b[0];
      x++;)
  // Chi
  y=0;
  R5(x=0;
     R5(b[x] = a[y+x]; x++;)
     x=0;
     R5(a[y+x] = b[x] ^ ~b[(x+1)%5] & b[(x+2)%5]; x++;)
     y+=5;
    )
  // Iota
  a[0] ^= RC[i];
  i++;
  )
}
