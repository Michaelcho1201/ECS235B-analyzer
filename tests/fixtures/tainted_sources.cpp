// Taint sources: scanf, getenv, recv, read, fgets
// Expected: tainted uses of variables derived from each source
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>

// scanf — classic taint source
void via_scanf() {
    char buf[128];
    scanf("%127s", buf);            // tainted: return writes into buf
    printf(buf);                    // WARNING: tainted variable 'buf' used
}

// getenv — environment variable taint
void via_getenv() {
    char *path = getenv("PATH");    // tainted: getenv return value
    system(path);                   // WARNING: tainted variable 'path' used
}

// fgets — file/stdin read
void via_fgets() {
    char line[256];
    fgets(line, sizeof(line), stdin); // tainted: fgets writes into line
    char *cmd = line;               // tainted: propagated from line
    system(cmd);                    // WARNING: tainted variable 'cmd' used
}

// recv — network taint source
void via_recv(int sockfd) {
    char data[512];
    recv(sockfd, data, sizeof(data), 0);  // tainted: recv writes into data
    printf(data);                          // WARNING: tainted variable 'data' used
}

// read — POSIX read taint source
void via_read(int fd) {
    char buf[64];
    read(fd, buf, sizeof(buf));     // tainted: read writes into buf
    printf(buf);                    // WARNING: tainted variable 'buf' used
}

// Taint propagation chain — should still warn at the end
void propagation_chain() {
    char raw[64];
    scanf("%63s", raw);             // raw is tainted
    char *copy = raw;               // copy is tainted (propagated)
    char *alias = copy;             // alias is tainted (propagated again)
    printf(alias);                  // WARNING: tainted variable 'alias' used
}

int main() {
    via_scanf();
    via_getenv();
    via_fgets();
    via_recv(3);
    via_read(4);
    propagation_chain();
    return 0;
}
