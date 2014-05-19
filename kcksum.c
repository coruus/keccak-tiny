#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define ENO(LABEL, MSG) \
  do {                 \
    if (err != 0) {    \
      perror(MSG);     \
      goto LABEL;      \
    }                  \
  } while (0)

#define E(LABEL, MSG)                         \
  do {                                        \
    if (err != 0) {                           \
      strerror_r(err, serr, 1024);            \
      fprintf(stderr, "%s: %s\n", serr, MSG); \
      goto LABEL;                             \
    }                                         \
  } while (0)

#define BITS 256
#define BYTES (BITS/8)
#define SHAFN sha3_256
extern int SHAFN(uint8_t*, size_t, uint8_t*, size_t);

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "filename required");
    return -1;
  }
  struct stat stat;
  int err = 0;
  char serr[1024] = {0};

  fprintf(stderr, "hashing '%s'", argv[1]);

  err = lstat(argv[1], &stat);
  ENO(ret, "couldn't stat");

  // Store the length of the file we statted.
  size_t llength = (size_t)stat.st_size;

  int fd = open(argv[1], O_RDONLY | O_NONBLOCK | O_NOFOLLOW);
  err = !fd;
  E(ret, "couldn't open");

  err = fstat(fd, &stat);
  E(close_file, "couldn't fstat");

  size_t length = (size_t)stat.st_size;
  if (length == 0) {
    E(close_file, "length-0 file");
  } else if (llength != length) {
    E(close_file,
      "fstat.st_len != lstat.st_len");
  }

  fprintf(stderr, ", length=%zu..\n", length);
  // Mmap
  uint8_t* in = mmap(0, length, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
  if (in == MAP_FAILED) {
    E(close_file, "mmap failed");
  }

  uint8_t out[BITS/8] = {0};
  fprintf(stderr, "..\n");
  err = SHAFN(out, BYTES, in, length);
  //err = vof(out, 32, in, length, 16);

  printf("SHA3-%u('%s') = ", BITS, argv[1]);
  for (size_t i = 0; i < BYTES; i++) {
    printf("%02x", out[i]);
  }
  printf("\n");
  fprintf(stderr, "..done.\n");
  munmap(in, length);

  close_file:
    close(fd);

  ret:
    return err;
}
