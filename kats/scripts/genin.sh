#!/usr/bin/env sh
tail +5 ShortMsgKAT.txt |
tr -s '\n' |
sed -e '/MD = ??/d;' |
cut -d ' ' -f 3 > input.txt&&
./scripts/genin.py input.txt
