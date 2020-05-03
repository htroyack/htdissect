#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
  int i = 0;
  int count = 256;

  if (argc == 2) {
    count = atoi(argv[1]);
    if (count <= 0 || count >= 256) {
      count = 256;
    }
  }


  for (i = 0; i < count; i++)
    putchar(i);
}
