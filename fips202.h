#ifndef FIPS202_H
#define FIPS202_H
#include "keccak.h"

#include <stdint.h>
#include <stdlib.h>

#define decshake(bits) \
  int shake##bits(uint8_t*, size_t, const uint8_t*, size_t);

#define decsha3(bits) \
  int sha3_##bits(uint8_t*, size_t, const uint8_t*, size_t);

decshake(128) //
decshake(256) //
decsha3(224)  //
decsha3(256)  //
decsha3(384)  //
decsha3(512)  //

#endif
