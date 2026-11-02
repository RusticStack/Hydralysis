/* One-off tool: finds two different names with the same FNV-1a 64 hash (rho search over f(h) = fnv1a64("rec_" +
   encode(h))). Its result is the colliding pair compiled into fnv_names.c. Not part of the build.
   usage: find_fnv_collision.exe [start]   (about 2-4 minutes) */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static const char ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

static void encode(uint64_t h, char *out) {
    memcpy(out, "rec_", 4);
    for (int i = 0; i < 11; ++i) { out[4 + i] = ALPHABET[(h >> (6 * (10 - i))) & 63]; }
    out[15] = 0;
}

static uint64_t f(uint64_t h) {
    char name[16];
    uint64_t hash = 14695981039346656037ull;
    encode(h, name);
    for (int i = 0; i < 15; ++i) { hash ^= (unsigned char)name[i]; hash *= 1099511628211ull; }
    return hash;
}

int main(int argc, char **argv) {
    uint64_t start = argc > 1 ? strtoull(argv[1], 0, 0) : 12345;
    uint64_t tortoise = f(start), hare = f(f(start));
    unsigned long long steps = 0;
    while (tortoise != hare) { tortoise = f(tortoise); hare = f(f(hare)); ++steps; }
    tortoise = start;
    uint64_t a = 0, b = 0;
    while (f(tortoise) != f(hare)) { tortoise = f(tortoise); hare = f(hare); }
    a = tortoise; b = hare;
    if (a == b) { printf("degenerate start\n"); return 1; }
    char na[16], nb[16];
    encode(a, na); encode(b, nb);
    printf("%s %s 0x%016llx 0x%016llx steps=%llu\n", na, nb, (unsigned long long)f(a), (unsigned long long)f(b), steps);
    return 0;
}
