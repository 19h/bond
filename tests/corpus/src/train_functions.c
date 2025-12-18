// Training corpus: Function call patterns
// Various function call/return patterns for HTM training

#include <stdint.h>

volatile int sink;

// Simple leaf function (no calls)
__attribute__((noinline))
int leaf_add(int a, int b) {
    return a + b;
}

// Simple leaf function
__attribute__((noinline))
int leaf_multiply(int a, int b) {
    return a * b;
}

// Function that calls other functions
__attribute__((noinline))
int caller_function(int a, int b, int c) {
    int sum = leaf_add(a, b);
    int product = leaf_multiply(sum, c);
    return product;
}

// Recursive function - factorial
__attribute__((noinline))
int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

// Recursive function - fibonacci
__attribute__((noinline))
int fibonacci(int n) {
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

// Tail-recursive helper
__attribute__((noinline))
int factorial_tail_helper(int n, int acc) {
    if (n <= 1) return acc;
    return factorial_tail_helper(n - 1, n * acc);
}

// Tail-recursive wrapper
__attribute__((noinline))
int factorial_tail(int n) {
    return factorial_tail_helper(n, 1);
}

// Multiple parameters function
__attribute__((noinline))
int many_params(int a, int b, int c, int d, int e, int f) {
    return a + b * c - d / (e + 1) + f;
}

// Function with local array (stack usage)
__attribute__((noinline))
int stack_array_func(int n) {
    int local_arr[32];
    for (int i = 0; i < 32 && i < n; i++) {
        local_arr[i] = i * i;
    }
    int sum = 0;
    for (int i = 0; i < 32 && i < n; i++) {
        sum += local_arr[i];
    }
    return sum;
}

// Function pointer call pattern
typedef int (*binary_op)(int, int);

__attribute__((noinline))
int apply_op(binary_op op, int a, int b) {
    return op(a, b);
}

// Chain of function calls
__attribute__((noinline))
int chain_a(int x) {
    return x + 1;
}

__attribute__((noinline))
int chain_b(int x) {
    return chain_a(x) * 2;
}

__attribute__((noinline))
int chain_c(int x) {
    return chain_b(x) - 3;
}

__attribute__((noinline))
int chain_d(int x) {
    return chain_c(x) + 4;
}

// Mutual recursion
__attribute__((noinline))
int is_even(int n);

__attribute__((noinline))
int is_odd(int n) {
    if (n == 0) return 0;
    return is_even(n - 1);
}

__attribute__((noinline))
int is_even(int n) {
    if (n == 0) return 1;
    return is_odd(n - 1);
}

// Variadic-like pattern (fixed args version)
__attribute__((noinline))
int sum_of_three(int a, int b, int c) {
    return a + b + c;
}

__attribute__((noinline))
int sum_of_five(int a, int b, int c, int d, int e) {
    return a + b + c + d + e;
}

int main() {
    sink = leaf_add(10, 20);
    sink = leaf_multiply(5, 6);
    sink = caller_function(2, 3, 4);
    sink = factorial(5);
    sink = fibonacci(10);
    sink = factorial_tail(6);
    sink = many_params(1, 2, 3, 4, 5, 6);
    sink = stack_array_func(20);
    sink = apply_op(leaf_add, 100, 200);
    sink = chain_d(10);
    sink = is_even(10);
    sink = is_odd(7);
    sink = sum_of_three(1, 2, 3);
    sink = sum_of_five(1, 2, 3, 4, 5);

    return 0;
}
