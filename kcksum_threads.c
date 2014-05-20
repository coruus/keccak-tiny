#include "f202.h"
#include "u.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

//#include <threads.h>

#define E(LABEL, MSG)                         \
  _(if (err != 0) {                           \
      strerror_r(err, serr, 1024);            \
      fprintf(stderr, "%s: %s\n", serr, MSG); \
      goto LABEL;                             \
    })

#ifdef VERBOSE
#define verbose(...) printf(__VA_ARGS__);
#else
#define verbose(...)
#endif

int h(char* fn);
int h(char* fn) {
  int err = 0;
  char serr[1024] = {0};
  fprintf(stderr, "hashing '%s', ", fn);

  int fd = open(fn, O_RDONLY | O_NONBLOCK | O_NOCTTY);
  err = !fd;
  E(ret, "couldn't open");

  struct stat stat;
  err = fstat(fd, &stat);
  E(close, "couldn't fstat");

  size_t length = (size_t)stat.st_size;
  fprintf(stderr, "length=%zu..\n", length);

  uint8_t* in = length ? mmap(0, length, PROT_READ, MAP_SHARED, fd, 0) : NULL;
  if (length && (in == MAP_FAILED)) { E(close, "mmap failed"); }

  uint8_t out[OBYTES] = {0};
  SHAFN(out, OBYTES, in, length);
  length && munmap(in, length);

  verbose("%s('%s') = ", NAME, fn);
  FOR(i, 1, OBYTES, printf("%02x", out[i]));
  verbose("\n");

close:
  close(fd);

ret:
  return err;
}

int main(int argc, char** argv) {
  int err = 0;

  for (int i = 1; i < argc; i++) {
    err |= h(argv[i]);
  }
  return err;
}
