// Unused variables in nested scopes (if / for / blocks).
#include <iostream>

int main() {
    int outer = 5;
    std::cout << outer << "\n";     // OK

    if (outer > 0) {
        int inner = outer * 2;      // WARNING: 'inner' never read inside this block
        int also_inner = 7;         // WARNING: 'also_inner' never read
    }

    for (int i = 0; i < 3; i++) {
        int loop_tmp = i + 1;       // WARNING: 'loop_tmp' assigned but never read
        std::cout << i << "\n";     // OK: 'i' is used
    }

    {
        int block_var = 100;        // WARNING: 'block_var' never read
    }

    // Variable used only for its side-effect via address — should NOT warn.
    int counter = 0;
    int *ptr = &counter;
    (*ptr)++;
    std::cout << counter << "\n";   // OK

    return 0;
}
