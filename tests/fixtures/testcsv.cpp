// vulnerable_test.cpp
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#endif

void test_gets() {
    char buffer[32];
    gets(buffer);   // vulnerable
}

void test_system() {
    char cmd[64] = "echo test";
    system(cmd);    // vulnerable
}

void test_popen() {
#ifndef _WIN32
    FILE* fp = popen("echo test", "r"); // vulnerable
    if (fp) pclose(fp);
#endif
}

#ifdef _WIN32
void test_winexec() {
    WinExec("calc.exe", SW_SHOW); // vulnerable
}

void test_shellexecute() {
    ShellExecuteA(NULL, "open", "calc.exe", NULL, NULL, SW_SHOW); // vulnerable
}

void test_shellexecuteex() {
    SHELLEXECUTEINFOA sei = {0};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = "open";
    sei.lpFile = "calc.exe";
    sei.nShow = SW_SHOW;

    ShellExecuteExA(&sei); // vulnerable
}
#endif

void test_string_functions() {
    char src[128] = "unsafe input";
    char dst[32];

    strcpy(dst, src);              // vulnerable
    strcat(dst, src);              // vulnerable
    sprintf(dst, "%s", src);       // vulnerable
}

void test_scan_functions() {
    char buffer[32];

    scanf("%s", buffer);           // vulnerable
    sscanf("long unsafe input", "%s", buffer); // vulnerable

    FILE* fp = fopen("input.txt", "r");
    if (fp) {
        fscanf(fp, "%s", buffer);  // vulnerable
        fclose(fp);
    }
}

void test_variadic_wrappers(const char* fmt, ...) {
    char buffer[32];
    va_list args;

    va_start(args, fmt);
    vsprintf(buffer, fmt, args);   // vulnerable
    va_end(args);

    va_start(args, fmt);
    vsscanf("unsafe input", fmt, args); // vulnerable
    va_end(args);

    FILE* fp = fopen("input.txt", "r");
    if (fp) {
        va_start(args, fmt);
        vfscanf(fp, fmt, args);    // vulnerable
        va_end(args);

        fclose(fp);
    }
}

void test_memory_functions() {
    char small[8];
    char large[64] = "this string is too large for destination";

    memcpy(small, large, sizeof(large));   // vulnerable
    memmove(small, large, sizeof(large));  // vulnerable
}

void test_temp_functions() {
    char name1[L_tmpnam];
    tmpnam(name1); // vulnerable

    char name2[] = "/tmp/fileXXXXXX";
    mktemp(name2); // vulnerable
}

int main() {
    test_gets();
    test_system();
    test_popen();

#ifdef _WIN32
    test_winexec();
    test_shellexecute();
    test_shellexecuteex();
#endif

    test_string_functions();
    test_scan_functions();
    test_variadic_wrappers("%s");
    test_memory_functions();
    test_temp_functions();

    return 0;
}