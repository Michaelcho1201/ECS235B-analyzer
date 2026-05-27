// Taint sources: argv, getopt, optarg
// Expected: tainted uses of argv-derived and getopt-derived variables
#include <cstdio>
#include <cstring>
#include <unistd.h>

// argv[1] directly passed to a function — tainted
void direct_argv(int argc, char **argv) {
    char *input = argv[1];          // tainted: argv
    printf(input);                  // WARNING: tainted variable 'input' used
}

// getopt — optarg is tainted
void via_getopt(int argc, char **argv) {
    int c;
    char *filename = nullptr;
    while ((c = getopt(argc, argv, "f:")) != -1) {
        if (c == 'f') {
            filename = optarg;      // tainted: optarg is a TAINT_GLOBAL
        }
    }
    if (filename) {
        FILE *f = fopen(filename, "r");  // WARNING: tainted variable 'filename' used
    }
}

// Sanitized path — should NOT warn
void sanitized_argv(int argc, char **argv) {
    char safe[256];
    snprintf(safe, sizeof(safe), "%s", argv[1]);  // snprintf is a sanitizer
    printf("%s\n", safe);                          // safe — no warning expected
}

int main(int argc, char **argv) {
    direct_argv(argc, argv);
    via_getopt(argc, argv);
    sanitized_argv(argc, argv);
    return 0;
}
