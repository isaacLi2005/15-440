#include <stdio.h>
#include <sys/types.h>

int main(void) {
    printf("sizeof(off_t) = %zu\n", sizeof(off_t));
    printf("sizeof(size_t) = %zu\n", sizeof(size_t));
    return 0;
}