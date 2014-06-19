env CPP="/usr/local/bin/gcc-4.8 -E -P -D__has_feature\(x\)=0 -I." frama-c -machdep x86_64 frama.c kck.c f202.c -val
