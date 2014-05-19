#ifndef F202_H
#define F202_H
#include "u.h"

#define decshake(bits) \
    int shake##bits(bytes, size, bytes, size);

decshake(128)
decshake(256)

#define decsha3(bits) \
    int sha3_##bits(bytes, size, bytes, size);

decsha3(224)
decsha3(256)
decsha3(384)
decsha3(512)

#define _(S) \
    do {     \
        S    \
    } while (0)
#define FOR(i, ST, L, S) \
    _(for (size i = 0; i < L; i += ST) { S; })

    // Can substitute an arbitrary permutation for Keccak-f.
    extern void keccakf(void*);
#define P keccakf
#define Plen 200

// Fold P*F over the full blocks of an input.
#define foldP(I, L, F)  \
    while (L >= rate) { \
        F(a, I, rate);  \
        P(a);           \
        I += rate;      \
        L -= rate;      \
    }

#define helper(NAME, S)                      \
    SIV NAME(bytes dst, bytes src, size len) \
    {                                        \
        FOR(i, 1, len, S);                   \
    }

#endif // F202_H
