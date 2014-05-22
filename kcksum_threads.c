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

#include "threads.h"

#define E(LABEL, MSG)                         \
  _(if (err != 0) {                           \
      strerror_r(err, serr, 1024);            \
      fprintf(stderr, "%s: '%s' %s\n", serr, fn, MSG); \
      goto LABEL;                             \
    })

#ifdef VERBOSE
#define verbose(...) printf(__VA_ARGS__);
#else
#define verbose(...)
#endif

#define nthreads 4

static mtx_t iomtx;

void h(void* v);
void h(void* v) {
  char* fn = (char*)v;
  int err = 0;
  char serr[1024] = {0};

  int fd = open(fn, O_RDONLY | O_NONBLOCK | O_NOCTTY);
  err = !fd;
  E(ret, "couldn't be opened.");

  struct stat stat;
  err = fstat(fd, &stat);
  E(close, "doesn't exist.");
  err = !!(stat.st_mode & S_IFDIR);
  E(close, "not a regular file.");

  size_t length = (size_t)stat.st_size;

  uint8_t* in = length ? mmap(0, length, PROT_READ, MAP_SHARED, fd, 0) : NULL;
  if (length && (in == MAP_FAILED)) { E(close, "mmap-ing failed."); }

  uint8_t out[OBYTES] = {0};
  SHAFN(out, OBYTES, in, length);
  length && munmap(in, length);

  mtx_lock(&iomtx);
  verbose("%s('%s') = ", NAME, fn);
  FOR(i, 1, OBYTES, printf("%02x", out[i]));
  verbose("\n");
  mtx_unlock(&iomtx);

close:
  close(fd);

ret:
  thrd_exit(err);
}

int main(int argc, char** argv) {
  int err = 0;

  mtx_init(&iomtx, mtx_plain);

  thrd_t t[nthreads];
  int res[nthreads];
  int i, j, k;
  for (i = 1; i < argc; i += nthreads) {
    for (j = 0; j < nthreads; j++) {
        if ((j+i) == argc) { goto join; }
        thrd_create(t + j, h, argv[i + j]);
     }
join:
    for (k = 0; k < j; k++) {
      err |= thrd_join(t[k], res + k);
      err |= res[k];
    }
  }
  return err;
}
