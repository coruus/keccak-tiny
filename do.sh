#!/usr/bin/env sh
cc=$(which gcc-4.9||which clang-3.5||which clang||which gcc)
$cc "-Dinline=__attribute__((__always_inline__))" -O3 -march=native -std=c11 -Wextra -Wpedantic -Wall -dynamic -shared keccak-tiny.c -o libkeccak-tiny.dylib
$cc -Os -march=native -std=c11 -Wextra -Wpedantic -Wall -dynamic -shared keccak-tiny.c -o libkeccak-tiny-small.dylib
