#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
  write(1, "write\n", 6);
  printf("printf\n");
  fprintf(stdout, "fprintf\n");
  vprintf("vprintf\n", NULL);
  vfprintf(stdout, "vfprintf\n", NULL);
  fputs("fputs\n", stdout);
  puts("puts"); // puts includes a newline char
  fwrite("fwrite\n", 7, 1, stdout);
}
