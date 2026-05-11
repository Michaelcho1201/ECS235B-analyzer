#include <iostream>
#include <string>

int main() {
    int a;
    int b = 10;
    int c;

    // --- if/else branches ---
    // 'a' is uninitialized on the true-branch (no init before use).
    // 'c' is only initialized on one branch, so it is possibly uninitialized
    // after the if/else when used below.
    if (b > 5) {
        int result = a + b;   // WARNING: 'a' used uninitialized
        std::cout << "result: " << result << "\n";
        c = result;
    } else {
        // c is NOT assigned here, so after the if/else c may be uninitialized
        std::cout << "b is small\n";
    }

    // c is possibly uninitialized (only set in the true branch above)
    std::cout << "c: " << c << "\n";    // WARNING: 'c' may be used uninitialized

    // --- nested if ---
    // 'd' is declared but never initialized; used inside a nested condition.
    int d;
    if (b > 0) {
        if (d > 0) {          // WARNING: 'd' used uninitialized
            std::cout << "d is positive\n";
        } else {
            d = 1;
        }
    }

    // --- while loop ---
    // 'i' is declared without an initializer; using it as the loop counter
    // is an uninitialized read.
    int i;
    while (i < b) {           // WARNING: 'i' used uninitialized
        std::cout << "i = " << i << "\n";
        i++;
    }

    // --- while with conditional init inside ---
    // 'x' is initialized only when the loop body executes; after the loop
    // its value is well-defined only if the body ran at least once.
    // The analyzer should flag first use of 'x' below the loop.
    int x;
    int counter = 0;
    while (counter < 3) {
        x = counter * 2;
        counter++;
    }
    // x is safe here because counter starts at 0 < 3, so the body always
    // runs — but a static analyzer cannot always prove that.
    std::cout << "x after loop: " << x << "\n";

    // --- clean path: no warnings expected below this line ---
    int e = 0;
    if (e == 0) {
        e = 42;
    }
    std::cout << "e: " << e << "\n";

    return 0;
}
