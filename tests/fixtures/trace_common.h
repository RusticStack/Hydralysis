/* Shared helpers of the semantic-trace fixtures (12.3-hydra.6, docs/trace-fixtures.md).
   Every program is deterministic in what it prints, finishes on its own and has a watchdog, so a hung run cannot
   stall a test. stdout carries "FX key=value" marker lines; the expected-answer file of each fixture
   (tests/fixtures/expected/<name>.json) states which lines, files and exit codes are exact. */
#ifndef TRACE_COMMON_H
#define TRACE_COMMON_H
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define FX __declspec(noinline)
#define FX_EXPORT __declspec(dllexport) __declspec(noinline)

static void say(const char *format, ...) {
    va_list args;
    va_start(args, format);
    printf("FX ");
    vprintf(format, args);
    printf("\n");
    fflush(stdout);
    va_end(args);
}

static DWORD WINAPI fx_watchdog_thread(LPVOID seconds) {
    Sleep((DWORD)(ULONG_PTR)seconds * 1000);
    fprintf(stderr, "FX watchdog fired\n");
    fflush(stderr);
    ExitProcess(99);
    return 0;
}

/* Bounded runtime: whatever happens, the process ends after this many seconds with exit code 99. */
static void fx_arm_watchdog(int seconds) {
    HANDLE thread = CreateThread(NULL, 0, fx_watchdog_thread, (LPVOID)(ULONG_PTR)seconds, 0, NULL);
    if (thread) CloseHandle(thread);
}

/* "--name=value" anywhere in argv; NULL when absent. */
static const char *fx_arg(int argc, char **argv, const char *prefix) {
    size_t length = strlen(prefix);
    for (int i = 1; i < argc; ++i)
        if (strncmp(argv[i], prefix, length) == 0) return argv[i] + length;
    return NULL;
}

static int fx_arg_int(int argc, char **argv, const char *prefix, int fallback) {
    const char *value = fx_arg(argc, argv, prefix);
    return value ? atoi(value) : fallback;
}

static int fx_flag(int argc, char **argv, const char *name) {
    for (int i = 1; i < argc; ++i)
        if (strcmp(argv[i], name) == 0) return 1;
    return 0;
}

/* Milliseconds of the monotonic clock (QueryPerformanceCounter), one clock domain for every process on the machine. */
static double fx_now_ms(void) {
    LARGE_INTEGER frequency, counter;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart * 1000.0 / (double)frequency.QuadPart;
}

static void fx_path(char *out, size_t size, const char *directory, const char *name) {
    _snprintf(out, size, "%s\\%s", directory, name);
    out[size - 1] = 0;
}
#endif
