void  *malloc(unsigned long size);
void  *calloc(unsigned long nmemb, unsigned long size);
void  *realloc(void *ptr, unsigned long size);
void   free(void *ptr);
char  *strdup(const char *s);
int    printf(const char *fmt, ...);

void simple_leak() {
    char *buf = (char *)malloc(128);
    buf[0] = 'A';
}

void no_leak() {
    char *buf = (char *)malloc(128);
    buf[0] = 'A';
    free(buf);
}

void conditional_leak(int flag) {
    char *buf = (char *)malloc(128);
    if (flag) {
        free(buf);
    }
}

void double_free_example() {
    char *buf = (char *)malloc(128);
    free(buf);
    free(buf);
}

void alias_free() {
    char *a = (char *)malloc(128);
    char *b = a;
    free(b);
}

char *returning_alloc() {
    char *buf = (char *)malloc(128);
    return buf;
}

void strdup_leak(const char *src) {
    char *copy = strdup(src);
    if (copy[0] == '\0') {}
}

void loop_leak(int n) {
    for (int i = 0; i < n; i++) {
        char *tmp = (char *)malloc(64);
        tmp[0] = (char)i;
    }
}

int early_return_clean(int flag) {
    char *buf = (char *)malloc(128);
    if (!buf) return -1;
    if (flag) {
        free(buf);
        return 0;
    }
    free(buf);
    return 1;
}

int leak_on_error(int flag) {
    char *buf = (char *)malloc(128);
    if (!flag) {
        return -1;
    }
    free(buf);
    return 0;
}

void calloc_leak(int n) {
    int *arr = (int *)calloc(n, sizeof(int));
    arr[0] = 42;
}

void alias_double_free() {
    char *a = (char *)malloc(128);
    char *b = a;
    free(a);
    free(b);
}
