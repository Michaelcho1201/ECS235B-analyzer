void  *malloc(unsigned long size);
void   free(void *ptr);
int    printf(const char *fmt, ...);

char *create_buffer(unsigned long size) {
    return (char *)malloc(size);
}

void destroy_buffer(void *ptr) {
    free(ptr);
}

void use_buffer(const char *ptr) {
    printf("%c\n", ptr[0]);
}

void caller_leak() {
    char *buf = create_buffer(128);
    use_buffer(buf);
}

void caller_clean() {
    char *buf = create_buffer(128);
    use_buffer(buf);
    destroy_buffer(buf);
}

char *factory(unsigned long size) {
    char *buf = create_buffer(size);
    return buf;
}

void factory_caller_leak() {
    char *p = factory(64);
    use_buffer(p);
}

void factory_caller_clean() {
    char *p = factory(64);
    use_buffer(p);
    destroy_buffer(p);
}
