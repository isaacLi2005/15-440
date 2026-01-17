#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

int main() {
    int fd = open("../README", O_RDONLY);
    fprintf(stderr, "open -> fd=%d errno=%d\n", fd, errno);

    int rc = close(fd);
    fprintf(stderr, "close -> rc=%d errno=%d\n", rc, errno);

    int rc2 = close(fd);
    printf("close2=%d errno=%d\n", rc2, errno);

    return 0;
}