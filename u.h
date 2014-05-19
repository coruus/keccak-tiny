#ifndef U_H
#define U_H
#include <stdlib.h>

#ifdef __clang__
#define INLINE __attribute__((always_inline))
#else
#define INLINE inline
#endif
#define SI static INLINE
#define SIV SI void
#define SIE SI int

typedef unsigned char byte;
typedef unsigned char* bytes;
typedef size_t size;
typedef unsigned long long u8;
#endif
