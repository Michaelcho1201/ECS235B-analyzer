// Fixtures for buffer-overflow-oriented checks.
#include <cstdio>
#include <cstring>

void overflow_by_constant_index()
{
    int a[3] = {0, 1, 2};
    a[3] = 7;
}

void overflow_in_loop_index()
{
    char buf[8] = {};
    for (int i = 0; i <= 8; i++) {
        buf[i] = 'x';
    }
}

void overflow_by_copy_calls()
{
    char small[4];
    strcpy(small, "hello");

    char dst[8] = "ab";
    strcat(dst, "123456");

    char src[16] = "0123456789";
    memcpy(dst, src, 16);
}

void scanf_cases()
{
    char input[8];
    scanf("%s", input);
    scanf("%12s", input);
    scanf("%7s", input);
}
