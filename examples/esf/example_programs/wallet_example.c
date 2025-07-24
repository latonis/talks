#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main() {
  const char *home = getenv("HOME");
  if (!home) {
    fprintf(stderr, "Could not get HOME environment variable.\n");
    return 1;
  }

  char path[4096];
  snprintf(path, sizeof(path), "%s/.wallet", home);

  FILE *file = fopen(path, "r");
  if (!file) {
    perror("Failed to open .wallet file");
    return 1;
  }

  printf("Successfully opened %s\n", path);
  fclose(file);
  return 0;
}