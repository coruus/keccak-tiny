/** A tiny, multi-threaded shasum utility. **/

#include "fips202.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "threads.h"

#define _(S) do { S } while (0)

#define E(LABEL, MSG)                                         \
  _(if (err != 0) {                                           \
      char serr[1024] = {0};                                  \
      strerror_r(err, serr, 1024);                            \
      mtx_lock(&iomtx);                                       \
      fprintf(stderr, "%s: '%s' %s\n", serr, filename, MSG);  \
      mtx_unlock(&iomtx);                                     \
      goto LABEL;                                             \
  })

#ifdef VERBOSE
#define verbose(...) printf(__VA_ARGS__);
#else
#define verbose(...) fprintf(stderr, __VA_ARGS__);
#endif

#ifndef SHAFN
#define SHAFN shake256
#endif
#ifndef OBYTES
#define OBYTES 64
#endif

#define nthreads 4

static mtx_t iomtx;

/** Escape a character and output it.
 *
 * @param c [in] The character to output.
 */
static inline void printescaped(char c) {
  if (   ((c >= 'A') && (c <= 'z'))
      || ((c >= 'a') && (c <= 'z'))
      || ((c >= '0') && (c <= '9'))
      || (c == '_') || (c == '-') || (c == '.')
      || (c == '/') || (c == ',') || (c == '+')
      || (c == ' ') || (c == '(') || (c == ')')) {
    verbose("%c", c);
  } else {
    verbose("\\x%02x", c);
  }
}

/** Hash a file.
 *
 * @param v [in] The filename.
 */
static inline void hash_file(void* v) {
  char* filename = (char*)v;
  int err = 0;

  int fd = open(filename, O_RDONLY | O_NONBLOCK | O_NOCTTY);
  err = !fd;
  E(ret, "couldn't be opened.");

  struct stat stat;
  err = fstat(fd, &stat);
  E(close, "doesn't exist.");
  err = !!(stat.st_mode & S_IFDIR);
  E(close, "not a regular file.");

  size_t length = (size_t)stat.st_size;

  uint8_t* in = length ? mmap(0, length, PROT_READ, MAP_SHARED, fd, 0) : NULL;
  if (length && (in == MAP_FAILED)) {
    E(close, "mmap-ing failed.");
  }

  uint8_t out[OBYTES] = {0};
  SHAFN(out, OBYTES, in, length);
  length&& munmap(in, length);

  // Take the IO mutex.
  mtx_lock(&iomtx);
  verbose("%s(\"", NAME);  // The function name
  // The (possibly escaped) filename
  while (*filename != 0) {
    printescaped(*filename);
    filename++;
  }
  verbose("\") = ");
  // And the hash output, in hexademical.
  for (int i = 0; i < OBYTES; i++) {
    printf("%02x", out[i]);
  }
  verbose("\n");
  // And release the IO mutex.
  mtx_unlock(&iomtx);

close:
  close(fd);

ret:
  thrd_exit(err);
}

int main(int argc, char** argv) {
  int err = 0;

  mtx_init(&iomtx, mtx_plain);

  thrd_t threads[nthreads];
  int result[nthreads];
  int i, j, k;
  for (i = 1; i < argc; i += nthreads) {
    for (j = 0; j < nthreads; j++) {
      if ((j + i) == argc) {
        goto join;
      }
      thrd_create(threads + j, hash_file, argv[i + j]);
    }
  join:
    for (k = 0; k < j; k++) {
      err |= thrd_join(threads[k], result + k);
      err |= result[k];
    }
  }
  mtx_destroy(&iomtx);
  return err;
}
