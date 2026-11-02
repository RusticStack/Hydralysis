/* A deadlock, and separately a handler that suspends all threads (spec 15.9, docs/trace-fixtures.md).
   usage: deadlock.exe --mode=deadlock|suspend-all [--hold=4] [--state-file=path] [--dump=path]
   Both modes: the main thread runs 20 frames of fx_main_frame (20 ms each, g_frame counts them); the "declared main
   loop" a watchdog watches is g_frame. When the bad state is reached the process writes --state-file (if given),
   prints "state=...", optionally writes a minidump of itself (--dump), and the reaper thread ends the process with
   exit code 0 --hold seconds later. The reaper (fx_reaper) and the fixture's own safety watchdog are the only
   threads that stay alive in the bad state.
   deadlock: after its frames the main thread takes lock A (fx_main_lock_a_then_b) while the worker takes lock B
     (fx_worker_b_then_a); each then waits for the other's lock forever. The main loop stops advancing.
   suspend-all: the main thread keeps running frames; a worker (fx_faulting_worker) dereferences a freed page; the
     vectored handler fx_suspend_all_handler suspends every thread but itself, the reaper and the watchdog, then waits
     inside the handler. The main loop stops advancing and the worker sits in the handler. */
#include "trace_common.h"
#include <tlhelp32.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

__declspec(dllexport) volatile LONG g_frame;
static CRITICAL_SECTION g_lock_a, g_lock_b;
static volatile LONG g_has_a, g_has_b, g_crossing, g_start_fault, g_state_reached;
static DWORD g_reaper_tid, g_watchdog_tid;
static const char *g_state_file, *g_dump, *g_state_name;
static int g_hold = 4;
static int g_mode_suspend;
static void *volatile g_freed;

FX void fx_main_frame(int frame) { InterlockedExchange(&g_frame, frame + 1); Sleep(20); }

FX void fx_main_lock_a_then_b(void) {
    EnterCriticalSection(&g_lock_a);
    InterlockedExchange(&g_has_a, 1);
    while (!g_has_b) Sleep(1);
    InterlockedIncrement(&g_crossing);
    EnterCriticalSection(&g_lock_b); /* never returns */
    LeaveCriticalSection(&g_lock_b);
    LeaveCriticalSection(&g_lock_a);
}

static DWORD WINAPI fx_worker_b_then_a(LPVOID unused) {
    (void)unused;
    EnterCriticalSection(&g_lock_b);
    InterlockedExchange(&g_has_b, 1);
    while (!g_has_a) Sleep(1);
    InterlockedIncrement(&g_crossing);
    EnterCriticalSection(&g_lock_a); /* never returns */
    LeaveCriticalSection(&g_lock_a);
    LeaveCriticalSection(&g_lock_b);
    return 0;
}

FX static void suspend_all_but_survivors(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 entry = { sizeof entry };
    DWORD self = GetCurrentThreadId(), pid = GetCurrentProcessId();
    if (snap == INVALID_HANDLE_VALUE) return;
    for (BOOL more = Thread32First(snap, &entry); more; more = Thread32Next(snap, &entry)) {
        if (entry.th32OwnerProcessID != pid || entry.th32ThreadID == self) continue;
        if (entry.th32ThreadID == g_reaper_tid || entry.th32ThreadID == g_watchdog_tid) continue;
        HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID);
        if (thread) { SuspendThread(thread); CloseHandle(thread); }
    }
    CloseHandle(snap);
}

FX static LONG CALLBACK fx_suspend_all_handler(EXCEPTION_POINTERS *info) {
    if (info->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        suspend_all_but_survivors();
        InterlockedExchange(&g_state_reached, 1);
        WaitForSingleObject(CreateEventA(NULL, TRUE, FALSE, NULL), INFINITE); /* the handler never returns */
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static DWORD WINAPI fx_faulting_worker(LPVOID unused) {
    (void)unused;
    while (!g_start_fault) Sleep(5);
    return *(volatile int *)g_freed;
}

static DWORD WINAPI fx_reaper(LPVOID unused) {
    (void)unused;
    if (g_mode_suspend) { while (!g_state_reached) Sleep(5); }
    else { while (g_crossing < 2) Sleep(5); Sleep(300); }
    if (g_state_file) {
        FILE *file = fopen(g_state_file, "wb");
        if (file) { fprintf(file, "%s frame=%ld\n", g_state_name, g_frame); fclose(file); }
    }
    say("state=%s", g_state_name);
    say("frames_before_freeze=%d", g_frame >= 20 ? 1 : 0);
    if (g_dump) {
        HANDLE file = CreateFileA(g_dump, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file != INVALID_HANDLE_VALUE) {
            BOOL ok = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), file,
                                        (MINIDUMP_TYPE)(MiniDumpWithDataSegs | MiniDumpWithThreadInfo | MiniDumpWithHandleData),
                                        NULL, NULL, NULL);
            CloseHandle(file);
            say("dump_written=%d", ok ? 1 : 0);
        }
    }
    Sleep((DWORD)g_hold * 1000);
    say("reaper exit");
    ExitProcess(0);
    return 0;
}

int main(int argc, char **argv) {
    const char *mode = fx_arg(argc, argv, "--mode=");
    if (!mode) { fprintf(stderr, "usage: deadlock --mode=deadlock|suspend-all\n"); return 2; }
    g_mode_suspend = strcmp(mode, "suspend-all") == 0;
    g_state_name = g_mode_suspend ? "suspended_all" : "deadlocked";
    g_hold = fx_arg_int(argc, argv, "--hold=", 4);
    g_state_file = fx_arg(argc, argv, "--state-file=");
    g_dump = fx_arg(argc, argv, "--dump=");
    InitializeCriticalSection(&g_lock_a);
    InitializeCriticalSection(&g_lock_b);
    HANDLE dog = CreateThread(NULL, 0, fx_watchdog_thread, (LPVOID)(ULONG_PTR)(g_hold + 40), 0, &g_watchdog_tid);
    HANDLE reaper = CreateThread(NULL, 0, fx_reaper, NULL, 0, &g_reaper_tid);
    (void)dog; (void)reaper;
    for (int frame = 0; frame < 20; ++frame) fx_main_frame(frame);
    say("frames=%ld", g_frame);
    if (g_mode_suspend) {
        g_freed = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        VirtualFree(g_freed, 0x1000, MEM_DECOMMIT);
        AddVectoredExceptionHandler(1, fx_suspend_all_handler);
        CreateThread(NULL, 0, fx_faulting_worker, NULL, 0, NULL);
        InterlockedExchange(&g_start_fault, 1);
        for (int frame = 20;; ++frame) fx_main_frame(frame);
    }
    CreateThread(NULL, 0, fx_worker_b_then_a, NULL, 0, NULL);
    fx_main_lock_a_then_b();
    return 7; /* unreachable while the deadlock holds */
}
