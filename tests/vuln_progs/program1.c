#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 700

int vul2(char *arg, char *buffer2)
{
  strcpy(buffer2, arg);
  return 0;
}

int vul1(char *argv[])
{
  char buffer[BUF_SIZE];
  vul2(argv[1], buffer);
}

int main(int argc, char *argv[])
{
  if (argc != 2)
    {
      fprintf(stderr, "program1: argc != 2\n");
      exit(EXIT_FAILURE);
    }
  vul1(argv);
  return 0;
}