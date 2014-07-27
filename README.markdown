# libkeccak-tiny

An implementation of the FIPS-202-defined SHA-3 and SHAKE functions
in 120 cloc (156 lines). One C file, one header.

The `Keccak-f[1600]` permutation is fully unrolled; it's nearly as fast
as the Keccak team's optimized permutation.

## Building

    > clang -O3 -march=native -std=c11 -Wextra -dynamic -shared keccak-tiny.c -o libkeccak-tiny.dylib

If you don't have a modern libc that includes the `memset_s` function,
you can just add `-D"memset_s(W,WL,V,OL)=memset(W,V,OL)` to the command
line.

## Using

Build the library, include the header, and do, e.g.,

    shake256(out, 256, in, inlen);

That's it.

(Note: You can request less output from the fixed-output-length
functions, but not more.)

## License

CC0
