// Baseline sample: no strcpy/gets/scanf-style calls flagged by the analyzer.
#include <iostream>
#include <string>

int main()
{
    std::string msg = "hello";
    std::cout << msg << '\n';
    return 0;
}
