typedef struct _FILE FILE;
FILE  *fopen(const char *path, const char *mode);
int    fclose(FILE *stream);
FILE  *popen(const char *command, const char *type);
int    pclose(FILE *stream);

int    open(const char *path, int flags, ...);
int    close(int fd);

int    socket(int domain, int type, int protocol);

typedef struct _DIR DIR;
DIR   *opendir(const char *name);
int    closedir(DIR *dirp);

void  *malloc(unsigned long size);
void   free(void *ptr);


void file_leak(const char *path) {
    FILE *fp = fopen(path, "r");
    (void)fp;
}

void file_clean(const char *path) {
    FILE *fp = fopen(path, "r");
    fclose(fp);
}

void pipe_leak(const char *cmd) {
    FILE *p = popen(cmd, "r");
    (void)p;
}

void pipe_clean(const char *cmd) {
    FILE *p = popen(cmd, "r");
    pclose(p);
}

void fd_leak(const char *path) {
    int fd = open(path, 0);
    (void)fd;
}

void fd_clean(const char *path) {
    int fd = open(path, 0);
    close(fd);
}

void socket_leak() {
    int sock = socket(2, 1, 0);
    (void)sock;
}

void socket_clean() {
    int sock = socket(2, 1, 0);
    close(sock);
}

void dir_leak(const char *path) {
    DIR *dir = opendir(path);
    (void)dir;
}

void dir_clean(const char *path) {
    DIR *dir = opendir(path);
    closedir(dir);
}
