#include <iostream>

int div_zero(int x) {
    if (x == 0) {
        return 10 / x;
    }

    return 0;
}

int null_deref(int *p) {
    if (p == nullptr) {
        return *p;
    }

    return 0;
}

int out_of_bounds(int i) {
    int arr[10];

    if (i >= 10) {
        return arr[i];
    }

    return 0;
}

int safe_div(int x) {
    if (x != 0) {
        return 10 / x;
    }

    return 0;
}