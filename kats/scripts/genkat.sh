#!/usr/bin/env sh
tail +3 ShortMsgKAT_${1}.txt |
tr -s '\n' |
sed -e '/Msg = /d;' |
cut -d ' ' -f 3 > ${1}.txt&&
./scripts/genkat.py ${1}.txt
