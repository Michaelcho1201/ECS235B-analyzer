// Clean file: every declared variable is read at least once — no warnings expected.
#include <iostream>
#include <string>

int square(int n) {
    return n * n;
}

int main() {
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

    return 0;
}
