#include <iostream>
#include <string>

// --- Basic unused variable cases ---

void test_basic() {
    int unused_local = 42;          // WARNING: declared and assigned, never read

    int used = 10;
    std::cout << used << "\n";      // OK: used is read

    int written_twice = 1;
    written_twice = 2;              // WARNING: written but value never read

    int declared_only;              // WARNING: declared, never assigned or read
}

// --- Unused variables in function parameters and multiple functions ---

// 'extra' is never used inside the function body.
int add(int a, int b, int extra) { // WARNING: 'extra' unused parameter
    return a + b;
}

// All parameters used — no warnings.
int multiply(int x, int y) {
    return x * y;
}

void process() {
    int temp = 99;                  // WARNING: 'temp' assigned but never read
    int result = multiply(3, 4);
    std::cout << result << "\n";
}

// --- Unused variables in nested scopes (if / for / blocks) ---

void test_scope() {
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
}

// --- Clean: every declared variable is read at least once — no warnings expected ---

int square(int n) {
    return n * n;
}

void test_clean() {
    int a = 3;
    int b = square(a);
    std::cout << b << "\n";

    std::string msg = "hello";
    std::cout << msg << "\n";

    for (int i = 0; i < 5; i++) {
        std::cout << i << " ";
    }
    std::cout << "\n";

    int x = 0;
    while (x < 3) {
        std::cout << x << "\n";
        x++;
    }
}

int main() {
    test_basic();
    std::cout << add(1, 2, 0) << "\n";
    process();
    test_scope();
    test_clean();
    return 0;
}
