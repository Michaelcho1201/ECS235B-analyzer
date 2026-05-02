// Intentionally uses unsafe C string APIs for analyzer testing.
#include <cstdio>
#include <cstring>

static void copy_cat_format_scan()
{
    char dest[64] = {};
    const char* src = "input";

    strcpy(dest, src);
    strcat(dest, "_suffix");

    char tmp[32];
    sprintf(tmp, "val=%d", 42);

    char user[16];
    scanf("%15s", user);
}

int main()
{
    copy_cat_format_scan();
    return 0;
}
