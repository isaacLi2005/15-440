#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *path = (argc > 1) ? argv[1] : "README";
    int fd = open(path, O_RDONLY);
    dprintf(2, "fd=%d errno=%d (%s)\n", fd, errno, strerror(errno));
    _exit(0);
}
