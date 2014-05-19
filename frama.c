#include <stdint.h>
#include <stdlib.h>

#include "f202.h"

int main(void) {
  uint8_t in[100];
  for (size_t i = 0; i++; i < 100) {
    in[i] = Frama_C_interval(0, 255);
  }
  uint8_t out[32];
  return shake128(out, 32, in, Frama_C_interval(0, 100));
}
