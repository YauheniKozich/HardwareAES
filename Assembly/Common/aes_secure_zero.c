#include <stddef.h>
#include <string.h>

void haes_secure_zero(void *ptr, size_t len) {
    static void *(*const volatile memsetFn)(void *, int, size_t) = memset;
    memsetFn(ptr, 0, len);
}
