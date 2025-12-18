// Training corpus: Control flow patterns
// Branching and conditional patterns for HTM training

#include <stdint.h>
#include <stddef.h>

volatile int sink;

// Simple if-else
__attribute__((noinline))
int simple_if_else(int x) {
    if (x > 0) {
        return x * 2;
    } else {
        return x * -2;
    }
}

// Chained if-else-if
__attribute__((noinline))
int chained_if(int x) {
    if (x < 0) {
        return -1;
    } else if (x == 0) {
        return 0;
    } else if (x < 10) {
        return 1;
    } else if (x < 100) {
        return 2;
    } else {
        return 3;
    }
}

// Switch statement (small)
__attribute__((noinline))
int small_switch(int x) {
    switch (x) {
        case 0: return 100;
        case 1: return 200;
        case 2: return 300;
        case 3: return 400;
        default: return -1;
    }
}

// Switch statement (larger - may generate jump table)
__attribute__((noinline))
int large_switch(int x) {
    switch (x) {
        case 0: return 10;
        case 1: return 20;
        case 2: return 30;
        case 3: return 40;
        case 4: return 50;
        case 5: return 60;
        case 6: return 70;
        case 7: return 80;
        case 8: return 90;
        case 9: return 100;
        default: return 0;
    }
}

// Ternary operator chain
__attribute__((noinline))
int ternary_chain(int a, int b, int c) {
    int max_ab = (a > b) ? a : b;
    int result = (max_ab > c) ? max_ab : c;
    return result;
}

// Short-circuit evaluation AND
__attribute__((noinline))
int short_circuit_and(int a, int b, int c) {
    if (a > 0 && b > 0 && c > 0) {
        return a + b + c;
    }
    return 0;
}

// Short-circuit evaluation OR
__attribute__((noinline))
int short_circuit_or(int a, int b, int c) {
    if (a > 100 || b > 100 || c > 100) {
        return 1;
    }
    return 0;
}

// Nested conditionals
__attribute__((noinline))
int nested_conditionals(int x, int y) {
    if (x > 0) {
        if (y > 0) {
            return 1; // First quadrant
        } else {
            return 4; // Fourth quadrant
        }
    } else {
        if (y > 0) {
            return 2; // Second quadrant
        } else {
            return 3; // Third quadrant
        }
    }
}

// Early return pattern
__attribute__((noinline))
int early_return(int* arr, int size) {
    if (arr == NULL) return -1;
    if (size <= 0) return -2;

    int sum = 0;
    for (int i = 0; i < size; i++) {
        if (arr[i] < 0) return -3;
        sum += arr[i];
    }
    return sum;
}

// Guard clause pattern
__attribute__((noinline))
int guard_clauses(int a, int b, int c) {
    if (a == 0) return 0;
    if (b == 0) return 0;
    if (c == 0) return 0;
    if (a < 0 || b < 0 || c < 0) return -1;

    return a * b * c;
}

// Complex boolean expression
__attribute__((noinline))
int complex_boolean(int a, int b, int c, int d) {
    if ((a > 0 && b > 0) || (c > 0 && d > 0)) {
        if (!(a == b && c == d)) {
            return 1;
        }
    }
    return 0;
}

// Bit flag checking
__attribute__((noinline))
int check_flags(unsigned int flags) {
    int count = 0;
    if (flags & 0x01) count++;
    if (flags & 0x02) count++;
    if (flags & 0x04) count++;
    if (flags & 0x08) count++;
    if (flags & 0x10) count++;
    if (flags & 0x20) count++;
    if (flags & 0x40) count++;
    if (flags & 0x80) count++;
    return count;
}

// Range checking
__attribute__((noinline))
int range_check(int x, int min, int max) {
    if (x < min) return min;
    if (x > max) return max;
    return x;
}

// State machine pattern
__attribute__((noinline))
int state_machine(int initial_state, int* inputs, int num_inputs) {
    int state = initial_state;
    for (int i = 0; i < num_inputs; i++) {
        switch (state) {
            case 0:
                state = (inputs[i] > 0) ? 1 : 0;
                break;
            case 1:
                state = (inputs[i] > 0) ? 2 : 0;
                break;
            case 2:
                state = (inputs[i] > 0) ? 2 : 1;
                break;
            default:
                state = 0;
        }
    }
    return state;
}

int main() {
    int arr[] = {1, 2, 3, 4, 5};
    int inputs[] = {1, 1, 0, 1, 1};

    sink = simple_if_else(5);
    sink = simple_if_else(-5);
    sink = chained_if(50);
    sink = small_switch(2);
    sink = large_switch(7);
    sink = ternary_chain(10, 20, 15);
    sink = short_circuit_and(1, 2, 3);
    sink = short_circuit_or(50, 150, 50);
    sink = nested_conditionals(1, -1);
    sink = early_return(arr, 5);
    sink = guard_clauses(2, 3, 4);
    sink = complex_boolean(1, 2, 3, 4);
    sink = check_flags(0xAB);
    sink = range_check(150, 0, 100);
    sink = state_machine(0, inputs, 5);

    return 0;
}
