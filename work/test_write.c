// test_write.c
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/stat.h>

/* Print errno nicely without relying on printf-formatting your library might intercept */
static void print_errno(const char *where) {
    int e = errno;
    fprintf(stderr, "%s: errno=%d (%s)\n", where, e, strerror(e));
}

static int write_all(int fd, const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < n) {
        ssize_t rv = write(fd, p + off, n - off);
        if (rv < 0) return -1;
        if (rv == 0) { errno = EIO; return -1; } // shouldn't happen for regular files
        off += (size_t)rv;
    }
    return 0;
}

static void dump_stat(const char *path) {
    struct stat st;
    if (stat(path, &st) < 0) {
        print_errno("stat");
        return;
    }
    fprintf(stderr, "stat(%s): size=%lld mode=%o\n",
            path, (long long)st.st_size, (unsigned)(st.st_mode & 0777));
}

static void test_stdout_not_remote(void) {
    // This is a good “sanity tripwire”: if your interposed write()
    // accidentally treats fd=1 as remote, your program output will vanish
    // or get sent to the server.
    const char *msg = "STDOUT sanity: if you see this, fd=1 stayed local.\n";
    ssize_t n = write(1, msg, strlen(msg));
    if (n < 0) print_errno("write(stdout)");
}

static void test_basic_create_trunc(const char *path) {
    fprintf(stderr, "\n== basic create/trunc/write/close ==\n");

    errno = 0;
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    fprintf(stderr, "open(O_CREAT|O_TRUNC|O_WRONLY) -> fd=%d\n", fd);
    if (fd < 0) { print_errno("open"); exit(1); }

    const char *msg = "hello from client\n";
    errno = 0;
    ssize_t n = write(fd, msg, strlen(msg));
    fprintf(stderr, "write(msg) -> n=%zd\n", n);
    if (n < 0) print_errno("write");

    errno = 0;
    int rc = close(fd);
    fprintf(stderr, "close -> rc=%d\n", rc);
    if (rc < 0) print_errno("close");
}

static void test_multiple_writes_and_append(const char *path) {
    fprintf(stderr, "\n== multiple writes + reopen append ==\n");

    int fd = open(path, O_WRONLY | O_APPEND);
    fprintf(stderr, "open(O_APPEND) -> fd=%d\n", fd);
    if (fd < 0) { print_errno("open append"); return; }

    const char *a = "line A\n";
    const char *b = "line B\n";
    if (write_all(fd, a, strlen(a)) < 0) print_errno("write_all(A)");
    if (write_all(fd, b, strlen(b)) < 0) print_errno("write_all(B)");

    int rc = close(fd);
    if (rc < 0) print_errno("close append");
}

static void test_zero_length_write(const char *path) {
    fprintf(stderr, "\n== zero-length write (should return 0) ==\n");

    int fd = open(path, O_WRONLY | O_APPEND);
    if (fd < 0) { print_errno("open"); return; }

    errno = 0;
    ssize_t n = write(fd, "", 0);
    fprintf(stderr, "write(len=0) -> n=%zd errno=%d\n", n, errno);

    close(fd);
}

static void test_binary_payload(const char *path) {
    fprintf(stderr, "\n== binary payload with NUL bytes ==\n");

    int fd = open(path, O_WRONLY | O_APPEND);
    if (fd < 0) { print_errno("open"); return; }

    uint8_t buf[32];
    for (int i = 0; i < (int)sizeof(buf); i++) buf[i] = (uint8_t)i;
    // include some zeros naturally (0, 1, 2, ...)
    if (write_all(fd, buf, sizeof(buf)) < 0) print_errno("write_all(binary)");

    close(fd);
}

static void test_error_cases(void) {
    fprintf(stderr, "\n== expected error cases ==\n");

    // Close on an invalid fd should fail with EBADF
    errno = 0;
    int rc = close(-123);
    fprintf(stderr, "close(-123) -> rc=%d\n", rc);
    if (rc < 0) print_errno("close(-123)");

    // Write on invalid fd should fail with EBADF
    const char *msg = "x";
    errno = 0;
    ssize_t n = write(-123, msg, 1);
    fprintf(stderr, "write(-123) -> n=%zd\n", n);
    if (n < 0) print_errno("write(-123)");

    // open a nonsense path (likely ENOENT)
    errno = 0;
    int fd = open("/definitely/not/a/real/path/15440_nope.txt", O_WRONLY);
    fprintf(stderr, "open(nonsense path) -> fd=%d\n", fd);
    if (fd < 0) print_errno("open(nonsense path)");
    if (fd >= 0) close(fd);
}

int main(void) {
    const char *path = "write_test.txt";

    test_stdout_not_remote();

    test_basic_create_trunc(path);
    dump_stat(path);

    test_multiple_writes_and_append(path);
    dump_stat(path);

    test_zero_length_write(path);
    dump_stat(path);

    test_binary_payload(path);
    dump_stat(path);

    test_error_cases();

    fprintf(stderr, "\nDone.\n");
    return 0;
}
