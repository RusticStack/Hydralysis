#include <windows.h>
#include <stdio.h>

typedef struct Sample { int health; int armor; } Sample;

__declspec(dllexport) __declspec(noinline)
int rustic_transform(Sample *sample, int delta) {
    int next = sample->health + delta;
    if (next > 100) next = 100;
    sample->health = next;
    return next + sample->armor;
}

__declspec(dllexport) __declspec(noinline)
int rustic_entry(int value) {
    Sample sample = { value, 7 };
    return rustic_transform(&sample, 3);
}

int main(int argc, char **argv) {
    FILE *output = argc > 2 ? fopen(argv[2], "w") : NULL;
    for (int step = 0; step < 6000; ++step) {
        if (argc > 1 && GetFileAttributesA(argv[1]) != INVALID_FILE_ATTRIBUTES) break;
        int result = rustic_entry(step % 90);
        if (output) { fprintf(output, "%d %d\n", step, result); fflush(output); }
        Sleep(50);
    }
    if (output) fclose(output);
    return 0;
}
