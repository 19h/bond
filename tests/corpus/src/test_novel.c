// Test binary: Novel patterns
// Contains patterns that are different from training corpus
// Used to test HTM's anomaly detection - these should show higher anomaly scores

#include <stdint.h>
#include <stddef.h>

volatile int sink;
volatile uint64_t sink64;

// SIMD-like manual unrolling - not in training corpus
__attribute__((noinline))
int vector_dot_product(int* a, int* b, int n) {
    int sum0 = 0, sum1 = 0, sum2 = 0, sum3 = 0;
    int i = 0;

    // Process 4 elements at a time
    for (; i + 3 < n; i += 4) {
        sum0 += a[i] * b[i];
        sum1 += a[i+1] * b[i+1];
        sum2 += a[i+2] * b[i+2];
        sum3 += a[i+3] * b[i+3];
    }

    // Handle remainder
    for (; i < n; i++) {
        sum0 += a[i] * b[i];
    }

    return sum0 + sum1 + sum2 + sum3;
}

// Bit manipulation tricks - not in training
__attribute__((noinline))
int count_set_bits(uint32_t n) {
    // Hamming weight / popcount
    n = n - ((n >> 1) & 0x55555555);
    n = (n & 0x33333333) + ((n >> 2) & 0x33333333);
    n = (n + (n >> 4)) & 0x0F0F0F0F;
    n = n + (n >> 8);
    n = n + (n >> 16);
    return n & 0x3F;
}

// Bit reversal - not in training
__attribute__((noinline))
uint32_t reverse_bits(uint32_t n) {
    n = ((n >> 1) & 0x55555555) | ((n & 0x55555555) << 1);
    n = ((n >> 2) & 0x33333333) | ((n & 0x33333333) << 2);
    n = ((n >> 4) & 0x0F0F0F0F) | ((n & 0x0F0F0F0F) << 4);
    n = ((n >> 8) & 0x00FF00FF) | ((n & 0x00FF00FF) << 8);
    return (n >> 16) | (n << 16);
}

// CRC-like computation - not in training
__attribute__((noinline))
uint32_t compute_checksum(const uint8_t* data, int len) {
    uint32_t crc = 0xFFFFFFFF;
    for (int i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return ~crc;
}

// Binary search - different from linear search in training
__attribute__((noinline))
int binary_search(int* arr, int n, int target) {
    int left = 0;
    int right = n - 1;

    while (left <= right) {
        int mid = left + (right - left) / 2;

        if (arr[mid] == target) {
            return mid;
        } else if (arr[mid] < target) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    return -1;
}

// Quick sort partition - not in training
__attribute__((noinline))
int partition(int* arr, int low, int high) {
    int pivot = arr[high];
    int i = low - 1;

    for (int j = low; j < high; j++) {
        if (arr[j] <= pivot) {
            i++;
            int temp = arr[i];
            arr[i] = arr[j];
            arr[j] = temp;
        }
    }

    int temp = arr[i + 1];
    arr[i + 1] = arr[high];
    arr[high] = temp;

    return i + 1;
}

// Hashing function - not in training
__attribute__((noinline))
uint32_t hash_djb2(const char* str) {
    uint32_t hash = 5381;
    int c;

    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }

    return hash;
}

// Integer square root - not in training
__attribute__((noinline))
uint32_t isqrt(uint32_t n) {
    if (n < 2) return n;

    uint32_t x = n;
    uint32_t y = (x + 1) / 2;

    while (y < x) {
        x = y;
        y = (x + n / x) / 2;
    }

    return x;
}

// GCD using Euclidean algorithm - not in training
__attribute__((noinline))
int gcd(int a, int b) {
    while (b != 0) {
        int t = b;
        b = a % b;
        a = t;
    }
    return a;
}

// Power function - different recursion pattern
__attribute__((noinline))
int64_t power(int base, int exp) {
    if (exp == 0) return 1;
    if (exp == 1) return base;

    int64_t half = power(base, exp / 2);
    if (exp % 2 == 0) {
        return half * half;
    } else {
        return half * half * base;
    }
}

// Ring buffer operations - not in training
typedef struct {
    int buffer[16];
    int head;
    int tail;
    int count;
} RingBuffer;

__attribute__((noinline))
void ring_push(RingBuffer* rb, int value) {
    if (rb->count < 16) {
        rb->buffer[rb->tail] = value;
        rb->tail = (rb->tail + 1) & 15;
        rb->count++;
    }
}

__attribute__((noinline))
int ring_pop(RingBuffer* rb) {
    if (rb->count > 0) {
        int value = rb->buffer[rb->head];
        rb->head = (rb->head + 1) & 15;
        rb->count--;
        return value;
    }
    return -1;
}

// Lookup table pattern - not in training
static const int lookup_table[16] = {
    0, 1, 1, 2, 1, 2, 2, 3,
    1, 2, 2, 3, 2, 3, 3, 4
};

__attribute__((noinline))
int nibble_popcount(uint32_t n) {
    int count = 0;
    while (n) {
        count += lookup_table[n & 0xF];
        n >>= 4;
    }
    return count;
}

// Packed struct operations - not in training
typedef struct __attribute__((packed)) {
    uint8_t flags;
    uint16_t id;
    uint32_t value;
} PackedData;

__attribute__((noinline))
uint32_t extract_packed(PackedData* p) {
    return ((uint32_t)p->flags << 24) |
           ((uint32_t)p->id << 8) |
           (p->value & 0xFF);
}

int main() {
    int arr[] = {1, 2, 3, 4, 5, 6, 7, 8};
    int sorted[] = {1, 3, 5, 7, 9, 11, 13, 15};
    uint8_t data[] = {0x12, 0x34, 0x56, 0x78};
    RingBuffer rb = {{0}, 0, 0, 0};
    PackedData pd = {0xFF, 0x1234, 0xABCDEF00};

    sink = vector_dot_product(arr, arr, 8);
    sink = count_set_bits(0xABCDEF12);
    sink = (int)reverse_bits(0x12345678);
    sink = (int)compute_checksum(data, 4);
    sink = binary_search(sorted, 8, 7);
    sink = partition(arr, 0, 7);
    sink = (int)hash_djb2("test string");
    sink = (int)isqrt(144);
    sink = gcd(48, 18);
    sink64 = power(2, 10);

    ring_push(&rb, 42);
    ring_push(&rb, 43);
    sink = ring_pop(&rb);

    sink = nibble_popcount(0xF0F0F0F0);
    sink = (int)extract_packed(&pd);

    return 0;
}
