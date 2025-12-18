// Training corpus: Mathematical operations
// Heavy arithmetic patterns for HTM training

#include <stdint.h>

volatile int64_t sink64;
volatile int sink;

// Basic arithmetic sequence - add, sub, mul, div
__attribute__((noinline))
int basic_arithmetic(int a, int b) {
    int sum = a + b;
    int diff = a - b;
    int prod = a * b;
    int quot = (b != 0) ? a / b : 0;
    return sum + diff + prod + quot;
}

// Bitwise operations - and, or, xor, shifts
__attribute__((noinline))
int bitwise_ops(int a, int b) {
    int and_result = a & b;
    int or_result = a | b;
    int xor_result = a ^ b;
    int left_shift = a << 2;
    int right_shift = b >> 1;
    return and_result + or_result + xor_result + left_shift + right_shift;
}

// Increment/decrement patterns
__attribute__((noinline))
int inc_dec_pattern(int start) {
    int val = start;
    val++;
    val++;
    val--;
    val += 10;
    val -= 5;
    val++;
    return val;
}

// Multiplication chain
__attribute__((noinline))
int64_t mult_chain(int a, int b, int c, int d) {
    int64_t r1 = (int64_t)a * b;
    int64_t r2 = r1 * c;
    int64_t r3 = r2 * d;
    return r3;
}

// Division and modulo
__attribute__((noinline))
int div_mod_pattern(int dividend, int divisor) {
    if (divisor == 0) return 0;
    int quotient = dividend / divisor;
    int remainder = dividend % divisor;
    int reconstructed = quotient * divisor + remainder;
    return reconstructed;
}

// Power of 2 operations (shifts)
__attribute__((noinline))
int power_of_two_ops(int val, int shift) {
    int doubled = val << 1;
    int quadrupled = val << 2;
    int halved = val >> 1;
    int shifted = val << shift;
    return doubled + quadrupled + halved + shifted;
}

// Absolute value pattern
__attribute__((noinline))
int abs_pattern(int a) {
    int mask = a >> 31;
    return (a + mask) ^ mask;
}

// Min/max patterns
__attribute__((noinline))
int min_max_pattern(int a, int b, int c) {
    int min_ab = (a < b) ? a : b;
    int min_abc = (min_ab < c) ? min_ab : c;
    int max_ab = (a > b) ? a : b;
    int max_abc = (max_ab > c) ? max_ab : c;
    return max_abc - min_abc;
}

// Compound assignment operators
__attribute__((noinline))
int compound_assign(int initial) {
    int val = initial;
    val += 100;
    val -= 50;
    val *= 2;
    val /= 3;
    val %= 7;
    val &= 0xFF;
    val |= 0x10;
    val ^= 0x05;
    return val;
}

int main() {
    sink = basic_arithmetic(42, 7);
    sink = bitwise_ops(0xABCD, 0x1234);
    sink = inc_dec_pattern(100);
    sink64 = mult_chain(2, 3, 4, 5);
    sink = div_mod_pattern(100, 7);
    sink = power_of_two_ops(16, 3);
    sink = abs_pattern(-42);
    sink = min_max_pattern(10, 20, 15);
    sink = compound_assign(1000);

    return 0;
}
