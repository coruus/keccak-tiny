#!/usr/bin/env sh
o=build/kats/${2}
mkdir -p $o
find kats/in -type f | parallel --verbose -j4 "./build/${1}sum {} > ${o}/{/}"
