#include "f202.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define ENO(LABEL, MSG) \
  _(if (err != 0) {    \
      perror(MSG);     \
      goto LABEL;      \
    })

#define E(LABEL, MSG)                         \
  do {                                        \
    if (err != 0) {                           \
      strerror_r(err, serr, 1024);            \
      fprintf(stderr, "%s: %s\n", serr, MSG); \
      goto LABEL;                             \
    }                                         \
  } while (0)

#ifdef VERBOSE
#define verbose(...) printf(__VA_ARGS__);
#else
#define verbose(...)
#endif

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "filename required");
    return -1;
  }
  struct stat stat;
  int err = 0;
  char serr[1024] = {0};

  fprintf(stderr, "hashing '%s'", argv[1]);

  int fd = open(argv[1], O_RDONLY | O_NONBLOCK | O_NOFOLLOW);
  err = !fd;
  E(ret, "couldn't open");

  err = fstat(fd, &stat);
  E(close_file, "couldn't fstat");

  size_t length = (size_t)stat.st_size;
  if (length == 0) {
    E(close_file, "length-0 file");
  }

  fprintf(stderr, ", length=%zu..\n", length);
  // Mmap
  uint8_t* in = mmap(0, length, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
  if (in == MAP_FAILED) {
    E(close_file, "mmap failed");
  }

  uint8_t out[OBYTES] = {0};
  err = SHAFN(out, OBYTES, in, length);

  verbose("%s('%s') = ", NAME, argv[1]);
  FOR(i, 1, OBYTES, printf("%02x", out[i]));
  verbose("\n");
  munmap(in, length);

  close_file:
    close(fd);

  ret:
    return err;
}
