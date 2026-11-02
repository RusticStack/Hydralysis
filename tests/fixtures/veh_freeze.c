/* A host whose vectored handler suspends every other thread on the first first-chance access violation
   (docs/trace-fixtures.md, spec 15.1). It froze real hosts with no crash and no dump.
   usage: veh_freeze.exe [--mode=wait|selftest] [--seconds=3] [--stop-file=path]
   wait (default): installs the handler (first in the chain), starts a heartbeat thread, frees an object with
     VirtualFree (its address is printed as "freed_object"), and then idles for --seconds, or until the stop file
     exists, so a probe can dereference the freed object from outside or inside. A probe that is non-faulting never
     runs the handler: handler_ran=0 and the heartbeat keeps advancing. A probe that faults runs the handler, which
     suspends the heartbeat (and, in a real host, everything else).
   selftest: the fixture dereferences the freed object itself inside __try; the handler runs and suspends the
     heartbeat, the faulting thread continues, observes the frozen heartbeat, resumes it and exits.
   The exported counters g_heartbeat and g_handler_ran are the observable state. */
#include "trace_common.h"
#include <tlhelp32.h>

__declspec(dllexport) volatile LONG g_heartbeat;
__declspec(dllexport) volatile LONG g_handler_ran;
__declspec(dllexport) volatile LONG g_suspended_threads;
static DWORD g_heartbeat_tid;
static void *volatile g_freed;
static int g_debugger;
static volatile int g_sink;

FX static void suspend_others(int suspend) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 entry = { sizeof entry };
    DWORD self = GetCurrentThreadId(), pid = GetCurrentProcessId();
    if (snap == INVALID_HANDLE_VALUE) return;
    for (BOOL more = Thread32First(snap, &entry); more; more = Thread32Next(snap, &entry)) {
        if (entry.th32OwnerProcessID != pid || entry.th32ThreadID == self) continue;
        if (entry.th32ThreadID == GetCurrentThreadId()) continue;
        HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID);
        if (!thread) continue;
        if (suspend) { if (SuspendThread(thread) != (DWORD)-1) InterlockedIncrement(&g_suspended_threads); }
        else ResumeThread(thread);
        CloseHandle(thread);
    }
    CloseHandle(snap);
}

FX static LONG CALLBACK fx_freezing_handler(EXCEPTION_POINTERS *info) {
    if (info->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        InterlockedIncrement(&g_handler_ran);
        suspend_others(1);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static DWORD WINAPI heartbeat_main(LPVOID unused) {
    (void)unused;
    for (;;) { InterlockedIncrement(&g_heartbeat); Sleep(10); }
}

FX int fx_read_object(const int *object) { return *object; }

/* Never dereferences OBJECT: it only records the address. A tracer hooking it can ask for OBJECT's bytes (the freed
   page) and must get a counted read failure, not a fault (spec 15.1). Called in wait mode with the freed address. */
FX int fx_probe_target(const void *object, int size) { g_sink = (int)(size_t)object ^ size; return size + g_sink * 0; }

int main(int argc, char **argv) {
    const char *mode = fx_arg(argc, argv, "--mode="), *stop = fx_arg(argc, argv, "--stop-file=");
    int seconds = fx_arg_int(argc, argv, "--seconds=", 3), selftest = mode && strcmp(mode, "selftest") == 0;
    fx_arm_watchdog(seconds + 20);
    g_debugger = IsDebuggerPresent();
    AddVectoredExceptionHandler(1, fx_freezing_handler);
    HANDLE thread = CreateThread(NULL, 0, heartbeat_main, NULL, 0, &g_heartbeat_tid);
    int *object = (int *)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    *object = 1234;
    VirtualFree(object, 0x1000, MEM_DECOMMIT); /* reserved, not committed: any access faults and nobody else can take the address */
    g_freed = object;
    say("debugger=%d", g_debugger);
    say("freed_object=0x%p", (void *)g_freed);
    say("ready");
    Sleep(200);
    if (selftest) {
        int faulted = 0;
        __try { g_sink = fx_read_object((const int *)g_freed); } __except (EXCEPTION_EXECUTE_HANDLER) { faulted = 1; }
        LONG before = g_heartbeat; /* the handler has already run: the heartbeat should stand still from here */
        Sleep(300);
        LONG after = g_heartbeat;
        say("faulted=%d handler_ran=%ld heartbeat_frozen=%d", faulted, g_handler_ran, after == before);
        suspend_others(0);
        say("done");
        return faulted && g_handler_ran == 1 ? 0 : 1;
    }
    LONG start = g_heartbeat;
    for (int waited = 0; waited < seconds * 20; ++waited) {
        if (stop && GetFileAttributesA(stop) != INVALID_FILE_ATTRIBUTES) break;
        if (waited % 4 == 0) fx_probe_target((const void *)g_freed, 16);
        Sleep(50);
    }
    LONG end = g_heartbeat;
    say("handler_ran=%ld heartbeat_advanced=%d", g_handler_ran, end > start);
    say("done");
    (void)thread;
    return 0;
}
