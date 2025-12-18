// Test binary: Mixed patterns
// Contains patterns similar to training corpus - should be recognized by trained HTM
// This tests that patterns learned from training transfer to new code

#include <stdint.h>
#include <stddef.h>

volatile int sink;
volatile int64_t sink64;

// Loop pattern - similar to train_loops.c
__attribute__((noinline))
int sum_array(int* arr, int n) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        total += arr[i];
    }
    return total;
}

// Nested loop - similar to train_loops.c
__attribute__((noinline))
int matrix_sum(int* matrix, int rows, int cols) {
    int sum = 0;
    for (int r = 0; r < rows; r++) {
        for (int c = 0; c < cols; c++) {
            sum += matrix[r * cols + c];
        }
    }
    return sum;
}

// Arithmetic pattern - similar to train_math.c
__attribute__((noinline))
int calculate(int x, int y, int z) {
    int a = x + y;
    int b = x - y;
    int c = x * y;
    int d = (y != 0) ? x / y : 0;
    return a + b + c + d + z;
}

// Bitwise operations - similar to train_math.c
__attribute__((noinline))
int apply_mask(unsigned int value, unsigned int mask) {
    unsigned int masked = value & mask;
    unsigned int inverted = value ^ mask;
    unsigned int combined = masked | (inverted >> 4);
    return (int)combined;
}

// String operation - similar to train_strings.c
__attribute__((noinline))
int string_length(const char* s) {
    int len = 0;
    while (s[len] != '\0') {
        len++;
    }
    return len;
}

// String compare - similar to train_strings.c
__attribute__((noinline))
int strings_equal(const char* a, const char* b) {
    while (*a && (*a == *b)) {
        a++;
        b++;
    }
    return (*a == *b);
}

// Control flow - similar to train_control.c
__attribute__((noinline))
int classify_value(int x) {
    if (x < 0) {
        return -1;
    } else if (x == 0) {
        return 0;
    } else if (x < 50) {
        return 1;
    } else if (x < 100) {
        return 2;
    } else {
        return 3;
    }
}

// Switch pattern - similar to train_control.c
__attribute__((noinline))
int lookup_value(int key) {
    switch (key) {
        case 0: return 1000;
        case 1: return 2000;
        case 2: return 3000;
        case 3: return 4000;
        case 4: return 5000;
        default: return -1;
    }
}

// Function call chain - similar to train_functions.c
__attribute__((noinline))
int add_one(int x) { return x + 1; }

__attribute__((noinline))
int double_val(int x) { return x * 2; }

__attribute__((noinline))
int process_chain(int x) {
    int a = add_one(x);
    int b = double_val(a);
    int c = add_one(b);
    return c;
}

// Recursive pattern - similar to train_functions.c
__attribute__((noinline))
int sum_recursive(int n) {
    if (n <= 0) return 0;
    return n + sum_recursive(n - 1);
}

// Early return guard pattern - similar to train_control.c
__attribute__((noinline))
int safe_divide(int a, int b) {
    if (b == 0) return 0;
    if (a == 0) return 0;
    return a / b;
}

// Memory copy pattern - similar to train_strings.c
__attribute__((noinline))
void copy_bytes(char* dst, const char* src, int n) {
    for (int i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

// Countdown loop - similar to train_loops.c
__attribute__((noinline))
int factorial_iter(int n) {
    int result = 1;
    for (int i = n; i > 1; i--) {
        result *= i;
    }
    return result;
}

// Compound assignment - similar to train_math.c
__attribute__((noinline))
int transform_value(int x) {
    int v = x;
    v += 10;
    v *= 2;
    v -= 5;
    v /= 3;
    v &= 0xFF;
    return v;
}

int main() {
    int arr[] = {1, 2, 3, 4, 5, 6, 7, 8};
    int matrix[] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    char buf[64];

    sink = sum_array(arr, 8);
    sink = matrix_sum(matrix, 3, 3);
    sink = calculate(10, 3, 5);
    sink = apply_mask(0xABCD, 0xFF00);
    sink = string_length("test string");
    sink = strings_equal("hello", "hello");
    sink = classify_value(75);
    sink = lookup_value(3);
    sink = process_chain(5);
    sink = sum_recursive(10);
    sink = safe_divide(100, 5);
    copy_bytes(buf, "copy test", 10);
    sink = factorial_iter(6);
    sink = transform_value(100);

    return 0;
}
