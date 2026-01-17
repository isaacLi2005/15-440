#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>

int main() {
    int fd = open("../README", O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }

    // Very distinctive 64-bit pattern (fits in signed 64-bit)
    off_t off = (off_t)0x0102030405060708ULL;

    off_t r = lseek(fd, off, SEEK_SET);
    if (r == (off_t)-1) {
        perror("lseek");
        return 1;
    }

    printf("client saw lseek return=%lld\n", (long long)r);
    close(fd);
    return 0;
}
