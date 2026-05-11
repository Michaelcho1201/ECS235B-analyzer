// Unused variables in function parameters and multiple functions.
#include <iostream>

// 'extra' is never used inside the function body.
int add(int a, int b, int extra) {  // WARNING: 'extra' unused parameter
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

int main() {
    std::cout << add(1, 2, 0) << "\n";
    process();
    return 0;
}
