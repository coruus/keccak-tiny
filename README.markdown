# kcksum

An implementation of Keccak, SHA-3, and SHAKE in 135 cloc.

A small (POSIX-only) sha3sum utility in 50 more.

Who said Keccak was complicated? And really, please stop using SHA1.

## Building

    > ninja

## Testing

All ShortMsgKATs from github.com/gvanas/KeccakCodePackage/TestVectors.
Do:

    > ./scripts/tests.sh
    ...
     0 files changed

## Using

Programs compiled with optimization:

   - *kck128sum*: SHAKE128 with 32 bytes of output
   - *kck256sum*: SHAKE256 with 64 bytes of output
   - *kck512sum*: SHA3_512 with 64 bytes of output

Programs compiled with ASan and UBSan:

    - *shake128sum*: SHAKE128 with 512 bytes of output
    - *shake256sum*: SHAKE256 with 512 bytes of output
    - *sha3_224sum*: SHA3-224
    - *sha3_256sum*: SHA3-256
    - *sha3_384sum*: SHA3-384
    - *sha3_512sum*: SHA3-512

## Endorsed by

Nobody.

## License

3BSD.
