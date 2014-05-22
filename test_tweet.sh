clang -march=native -O3 -std=c99 -Wall -Wextra -Weverything -Wpedantic kcksum_tweet.c -include kcksum_tweet.h -isystem. -o build/tshake256 &&
#gcc -march=native -O3 -std=c11 -fsanitize=address -fsanitize=undefined -Wall -Wpedantic kcksum_tweet.c -include kcksum_tweet.h -isystem. -o build/tshake256 &&
./build/tshake256 kats/in/* | gsort -t/ -k 3 -n > build/tshake.txt &&
./build/kck256sum kats/in/* | gsort -t/ -k 3 -n > build/shake.txt &&
diff build/shake.txt build/tshake.txt | diffstat
