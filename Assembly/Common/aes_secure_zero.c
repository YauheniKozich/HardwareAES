#include <stddef.h>
#include <stdint.h>
#include <string.h>

void haes_secure_zero(void *ptr, size_t len) {
    static void *(*const volatile memsetFn)(void *, int, size_t) = memset;
    memsetFn(ptr, 0, len);
}

int haes_constant_time_equal(const uint8_t *lhs, const uint8_t *rhs, size_t len) {
    if (!lhs || !rhs) return 0;

    volatile uint8_t difference = 0;
    for (size_t index = 0; index < len; index++) {
        difference |= (uint8_t)(lhs[index] ^ rhs[index]);
    }
    return difference == 0;
}
