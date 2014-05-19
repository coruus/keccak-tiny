#ifndef U_H
#define U_H
#include <stdlib.h>

#ifndef INLINE
#define INLINE inline
#endif  // INLINE
#define SI static INLINE
#define SIV SI void
#define SIE SI int

typedef unsigned char byte;
typedef unsigned char* bytes;
typedef size_t size;
typedef unsigned long long u8;

#define _(S) \
    do {     \
        S    \
    } while (0)
#define FOR(i, ST, L, S) \
    _(for (size i = 0; i < L; i += ST) { S; })

#define mkapply(NAME, S)                     \
    SIV NAME(bytes dst, bytes src, size len) \
    {                                        \
        FOR(i, 1, len, S);                   \
    }


#endif
