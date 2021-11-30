#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

#include <unistd.h>
#include <sys/syscall.h>

/* Function pointers to hold the value of the glibc functions */
extern int (__real_printf)(const char *fmt, ...);
extern int (__real_fprintf)(FILE * stream, const char *fmt, ...);
extern int (__real_vprintf)(const char *fmt, va_list args);
extern int (__real_vfprintf)(FILE * stream, const char *fmt, va_list args);
//extern ssize_t (__real_write)(int fd, const void *buf, size_t count);
extern int (__real_fputs)(const char *str, FILE *stream);
extern int (__real_puts)(const char *str);
extern size_t (__real_fwrite)(const void *ptr, size_t size, size_t count, FILE *stream);

// hashfuzz boundary values for the hashing functions
unsigned char boundary[3] = {0};

void updateHashfuzzClass(const char *str, int len);

int __wrap_printf(const char *fmt, ...) {
  static char buf[65536];
  va_list args;
  va_start(args, fmt);
  int ret = vsprintf(buf, fmt, args);
  va_end(args);

  updateHashfuzzClass(buf, ret);
  ret = __real_printf(buf);

  return ret;
}

int __wrap_fprintf(FILE * stream, const char *fmt, ...) {
  static char buf[65536];
  va_list args;
  va_start(args, fmt);
  int ret = vsprintf(buf, fmt, args);
  va_end(args);

  updateHashfuzzClass(buf, ret);
  ret = fprintf(stream, "%s", buf);

  return ret;
}

int __wrap_vprintf(const char *fmt, va_list args) {
  static char buf[65536];
  int ret = vsprintf(buf, fmt, args);
  updateHashfuzzClass(buf, ret);

  return __real_vprintf(buf, args);
}

int __wrap_vfprintf(FILE * stream, const char *fmt, va_list args) {
  static char buf[65536];
  int ret = vsprintf(buf, fmt, args);
  updateHashfuzzClass(buf, ret);

  return __real_vfprintf(stream, buf, args);
}

// ssize_t __wrap_write(int fd, const void *buf, size_t count) {
//   updateHashfuzzClass(buf, count);
//   ssize_t result = __real_write(fd, buf, count);
//   return result;
// }

int __wrap_puts(const char *str) {
  updateHashfuzzClass(str, strlen(str));
  return __real_puts(str);
}

int __wrap_fputs(const char *str, FILE *stream) {
  updateHashfuzzClass(str, strlen(str));
  updateHashfuzzClass("\n", 1);
  return __real_fputs(str, stream);
}

size_t __wrap_fwrite(const void *ptr, size_t size, size_t count, FILE *stream) {
  updateHashfuzzClass(ptr, size * count);
  return __real_fwrite(ptr, size, count, stream);
}

// General hashfuzz functions

void initHashfuzz(int argc, char *argv[]) {
  if (argc != 4) {
    __real_printf("Expected 4 args in initHashfuzz\n");
    exit(1);
  }

  char *endptr;
  for (int i = 0; i < 3; i++) {
    char *startptr = argv[i + 1];
    long read = strtol(startptr, &endptr, 10);

    if (endptr == startptr) {
      __real_printf("Failed to read a number at arg %d (%s)\n", i + 1, startptr);
      exit(1);
    }

    if (read < 0 || read > 255) {
      __real_printf("Arg %d (%s) was < 0 or > 255 (value: %ld)\n", 
             i + 1, startptr, read);
      exit(1);
    }

    boundary[i] = read;
  }

  for (int i = 0; i < 2; i++) {
    for (int j = i + 1; j < 3; j++) {
      if (boundary[i] == boundary[j]) {
        __real_printf("boundary[%d] == boundary[%d] (%hhu == %hhu)\n", 
                      i, j, boundary[i], boundary[j]);
        exit(1);
      }
    }
  }
}

void printError(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
  exit(1);
}

int findParity(int x)
{
  int y = x ^ (x >> 1);
  y = y ^ (y >> 2);
  y = y ^ (y >> 4);
  y = y ^ (y >> 8);
  y = y ^ (y >> 16);

  if (y & 1)
    return 1;
  return 0;
}

void updateHashfuzzClass(const char *str, int len) {
  static time_t t = 0;
  static unsigned char currentClass[3] = {0};

  if (boundary[0] == 0 && 
      boundary[0] == boundary[1] && 
      boundary[1] == boundary[2]) {
    char *buf = "Hashfuzz uninitialised\n";
    __real_printf(buf);

    srand(time(&t));
    int rnd = rand();
    boundary[0] = rnd & 0xFF;
    boundary[1] = (rnd >> 8) & 0xFF;
    boundary[2] = (rnd >> 16) & 0xFF;
  }
  
  unsigned char class = 0;
  for (int i = 0; i < 3; i++) {
    for (int j = 0; j < len; j++) {
      currentClass[i] = (currentClass[i] + findParity(boundary[i] & str[j])) % 2;
    }
    class |= currentClass[i] << i;
  }

  char buf[40];
  len = sprintf(buf, "<HFCLASS:%hhu>", class);
  __real_puts(buf);
}
