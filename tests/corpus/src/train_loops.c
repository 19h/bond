// Training corpus: Loop patterns
// This file contains various loop constructs for HTM training

#include <stdint.h>

// Prevent optimization from removing our code
volatile int sink;

// Simple counting loop - generates: mov, add, cmp, jl pattern
__attribute__((noinline))
int simple_count_loop(int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += i;
    }
    return sum;
}

// Nested loop - generates nested loop patterns
__attribute__((noinline))
int nested_loop(int rows, int cols) {
    int total = 0;
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            total += i * j;
        }
    }
    return total;
}

// While loop with early exit
__attribute__((noinline))
int while_loop_search(int* arr, int size, int target) {
    int i = 0;
    while (i < size) {
        if (arr[i] == target) {
            return i;
        }
        i++;
    }
    return -1;
}

// Do-while loop
__attribute__((noinline))
int do_while_loop(int start) {
    int val = start;
    do {
        val = val * 2 + 1;
    } while (val < 1000);
    return val;
}

// Loop with multiple increments
__attribute__((noinline))
int stride_loop(int* arr, int size) {
    int sum = 0;
    for (int i = 0; i < size; i += 4) {
        sum += arr[i];
        if (i + 1 < size) sum += arr[i + 1];
        if (i + 2 < size) sum += arr[i + 2];
        if (i + 3 < size) sum += arr[i + 3];
    }
    return sum;
}

// Countdown loop
__attribute__((noinline))
int countdown_loop(int n) {
    int product = 1;
    for (int i = n; i > 0; i--) {
        product *= i;
        if (product > 1000000) break;
    }
    return product;
}

int main() {
    int arr[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    sink = simple_count_loop(100);
    sink = nested_loop(10, 10);
    sink = while_loop_search(arr, 10, 5);
    sink = do_while_loop(1);
    sink = stride_loop(arr, 10);
    sink = countdown_loop(10);

    return 0;
}
