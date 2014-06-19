#!/usr/bin/env sh
cf=clang-format
find . -name "*.c" -o -name "*.h" | parallel "${cf} -i -style=file {}"
