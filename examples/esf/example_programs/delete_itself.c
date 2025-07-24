#include <limits.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  char path[PATH_MAX];
  uint32_t size = sizeof(path);

  if (_NSGetExecutablePath(path, &size) != 0) {
    fprintf(stderr, "Failed to get executable path\n");
    return 1;
  }

  printf("Running program. Will delete: %s\n", path);

  if (unlink(path) != 0) {
    perror("Failed to delete self");
    return 1;
  }

  printf("Deleted self successfully.\n");
  return 0;
}