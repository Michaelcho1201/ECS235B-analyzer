// Basic unused variable cases.
#include <iostream>

int main() {
    int unused_local = 42;          // WARNING: declared and assigned, never read

    int used = 10;
    std::cout << used << "\n";      // OK: used is read

    int written_twice = 1;
    written_twice = 2;              // WARNING: written but value never read

    int declared_only;              // WARNING: declared, never assigned or read

    return 0;
}
