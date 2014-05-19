#!/usr/bin/env python
from __future__ import division, print_function

from binascii import unhexlify
import sys
from more_itertools import grouper

with open(sys.argv[1]) as f:
    lines = f.read().split('\n')[:-1]

for len, msg in grouper(2, lines):
    len = int(len)
    if len % 8 != 0:
        continue
    with open('in/{}'.format(len), 'wb') as f:
        f.write(unhexlify(msg))
