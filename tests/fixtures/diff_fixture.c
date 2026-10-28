/* Two builds of one program for the cross-build checks (docs/verification-fixtures.md).
   Build 1 is the default; build 2 is -DV2. Ground truth comes from each build's linker
   map (build_fixtures.py), never from names Hydralysis could read:
     same      df_parse, df_checksum, df_format, df_scale, df_lookup, df_walk  identical code
     moved     df_render, df_mix                    identical code, placed elsewhere in V2
     changed   df_limit (threshold), df_banner (string and an extra call)
     added     df_added (V2 only)
     removed   df_removed (build 1 only) */
#include <stdio.h>
#include <string.h>

#define DF __declspec(noinline)

volatile int g_sink;
static int table[16] = { 3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3 };

#ifdef V2
DF int df_mix(int a, int b) { return (a * 31) ^ (b >> 3) ^ 0x5bd1e995; }
#endif

DF int df_parse(const char *text) {
    int value = 0;
    while (*text >= '0' && *text <= '9') value = value * 10 + (*text++ - '0');
    return value;
}

DF unsigned df_checksum(const unsigned char *data, int size) {
    unsigned sum = 2166136261u;
    for (int i = 0; i < size; ++i) sum = (sum ^ data[i]) * 16777619u;
    return sum;
}

#ifndef V2
DF int df_render(int frame) { return table[frame & 15] * 7 + frame / 3; }
#endif

DF int df_format(char *out, int size, int value) { return snprintf(out, size, "value=%d units", value); }

DF int df_limit(int value) {
#ifdef V2
    return value > 250 ? 250 : value;
#else
    return value > 100 ? 100 : value;
#endif
}

DF float df_scale(float value, int steps) {
    for (int i = 0; i < steps; ++i) value = value * 1.5f - 0.25f;
    return value;
}

#ifndef V2
DF int df_removed(int value) { return table[value & 15] + table[(value >> 4) & 15] * 100; }
#endif

DF int df_lookup(const char *key) {
    static const char *keys[] = { "alpha", "beta", "gamma", "delta" };
    for (int i = 0; i < 4; ++i) if (strcmp(keys[i], key) == 0) return i;
    return -1;
}

DF const char *df_banner(void) {
#ifdef V2
    g_sink += df_limit(g_sink);
    return "diff fixture build two";
#else
    return "diff fixture build one";
#endif
}

#ifndef V2
DF int df_mix(int a, int b) { return (a * 31) ^ (b >> 3) ^ 0x5bd1e995; }
#endif

DF int df_walk(int start) {
    int at = start, steps = 0;
    while (at != 1 && steps < 1000) { at = (at & 1) ? at * 3 + 1 : at / 2; ++steps; }
    return steps;
}

#ifdef V2
DF int df_render(int frame) { return table[frame & 15] * 7 + frame / 3; }
DF int df_added(int value) { return df_walk(value) * df_mix(value, 3) + (int)strlen(df_banner()); }
#endif

int main(int argc, char **argv) {
    char buffer[64];
    unsigned char bytes[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    int value = df_parse(argc > 1 ? argv[1] : "42");
    g_sink = df_limit(value) + (int)df_checksum(bytes, 8) + df_format(buffer, 64, value) + df_render(value)
           + (int)df_scale(1.0f, 3) + df_lookup("gamma") + df_mix(value, 9) + df_walk(27) + (int)strlen(df_banner());
#ifdef V2
    g_sink += df_added(value);
#else
    g_sink += df_removed(value);
#endif
    printf("%d\n", g_sink);
    return 0;
}
