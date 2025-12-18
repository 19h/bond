// Training corpus: String operations
// String manipulation patterns for HTM training

#include <stdint.h>
#include <stddef.h>

volatile int sink;
volatile char sink_char;

// Manual strlen - generates rep scasb or loop pattern
__attribute__((noinline))
size_t my_strlen(const char* str) {
    size_t len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}

// Manual strcpy - generates load/store loop
__attribute__((noinline))
char* my_strcpy(char* dest, const char* src) {
    char* ret = dest;
    while ((*dest++ = *src++) != '\0');
    return ret;
}

// Manual strcmp - generates comparison loop
__attribute__((noinline))
int my_strcmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

// Character search
__attribute__((noinline))
const char* my_strchr(const char* str, int c) {
    while (*str != '\0') {
        if (*str == (char)c) {
            return str;
        }
        str++;
    }
    return (c == '\0') ? str : (const char*)0;
}

// Reverse string in place
__attribute__((noinline))
void reverse_string(char* str, size_t len) {
    if (len <= 1) return;
    size_t i = 0;
    size_t j = len - 1;
    while (i < j) {
        char temp = str[i];
        str[i] = str[j];
        str[j] = temp;
        i++;
        j--;
    }
}

// Count character occurrences
__attribute__((noinline))
int count_char(const char* str, char c) {
    int count = 0;
    while (*str) {
        if (*str == c) {
            count++;
        }
        str++;
    }
    return count;
}

// To uppercase
__attribute__((noinline))
void to_upper(char* str) {
    while (*str) {
        if (*str >= 'a' && *str <= 'z') {
            *str = *str - 32;
        }
        str++;
    }
}

// To lowercase
__attribute__((noinline))
void to_lower(char* str) {
    while (*str) {
        if (*str >= 'A' && *str <= 'Z') {
            *str = *str + 32;
        }
        str++;
    }
}

// String contains substring (naive)
__attribute__((noinline))
int contains_substr(const char* haystack, const char* needle) {
    if (*needle == '\0') return 1;

    while (*haystack) {
        const char* h = haystack;
        const char* n = needle;

        while (*h && *n && (*h == *n)) {
            h++;
            n++;
        }

        if (*n == '\0') return 1;
        haystack++;
    }
    return 0;
}

// Memory set
__attribute__((noinline))
void* my_memset(void* dest, int c, size_t n) {
    unsigned char* p = dest;
    while (n--) {
        *p++ = (unsigned char)c;
    }
    return dest;
}

// Memory copy
__attribute__((noinline))
void* my_memcpy(void* dest, const void* src, size_t n) {
    unsigned char* d = dest;
    const unsigned char* s = src;
    while (n--) {
        *d++ = *s++;
    }
    return dest;
}

int main() {
    char buffer[256];
    char buffer2[256];
    const char* test_str = "Hello, World!";

    sink = (int)my_strlen(test_str);
    my_strcpy(buffer, test_str);
    sink = my_strcmp(buffer, test_str);
    sink = (my_strchr(test_str, 'W') != NULL);
    my_strcpy(buffer, "reverse");
    reverse_string(buffer, 7);
    sink = count_char(test_str, 'l');
    my_strcpy(buffer, "HELLO");
    to_lower(buffer);
    my_strcpy(buffer, "hello");
    to_upper(buffer);
    sink = contains_substr(test_str, "World");
    my_memset(buffer, 'X', 10);
    my_memcpy(buffer2, buffer, 10);

    return 0;
}
