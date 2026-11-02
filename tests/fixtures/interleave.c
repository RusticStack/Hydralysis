/* Two unrelated operations interleave; identities are reused (docs/trace-fixtures.md, spec 14.2 and 14.3).
   usage: interleave.exe            (the parent; spawns itself twice with --child)
   Two worker pools (P: ops 1000..1007, Q: ops 2000..2007, two threads each) take correlated requests from one
   submitting thread, alternating P and Q. Request op N travels fx_submit(N) -> queue -> fx_handle_request(N) on a
   worker -> fx_store_result(N) -> fx_complete(N); result(N) = N*3 + pool number. Op 9999 is submitted to pool Q
   but dropped before the queue: a request with no handler, which an explanation must report as a missing link.
   Then: a handle value, a virtual address and a module base are reused; the parent spawns a child twice. */
#include "trace_common.h"

#define POOLS 2
#define PER_POOL 8
#define QUEUE 32

typedef struct Pool {
    int number;
    int items[QUEUE];
    int head, tail;
    CRITICAL_SECTION lock;
    HANDLE ready;
    HANDLE threads[2];
} Pool;

static Pool g_pools[POOLS];
static volatile LONG g_completed;
static volatile LONG g_results[POOLS * PER_POOL];
static HANDLE g_all_done;

FX int fx_submit(int pool, int op) {
    Pool *p = &g_pools[pool];
    EnterCriticalSection(&p->lock);
    p->items[p->tail++ % QUEUE] = op;
    LeaveCriticalSection(&p->lock);
    ReleaseSemaphore(p->ready, 1, NULL);
    return op;
}

/* The dropped request: counted as submitted, never queued, so no handler ever sees it. */
static volatile LONG g_dropped;
FX int fx_submit_dropped(int pool, int op) {
    (void)pool;
    InterlockedIncrement(&g_dropped);
    return op;
}

FX void fx_store_result(int op, int value) {
    int slot = (op / 1000 - 1) * PER_POOL + op % 1000;
    g_results[slot] = value;
}

FX void fx_complete(int op) {
    (void)op;
    if (InterlockedIncrement(&g_completed) == POOLS * PER_POOL) SetEvent(g_all_done);
}

FX int fx_handle_request(int pool, int op, int worker) {
    Sleep(2 + worker);
    int value = op * 3 + pool;
    fx_store_result(op, value);
    fx_complete(op);
    return value;
}

static DWORD WINAPI worker_main(LPVOID parameter) {
    int pool = (int)((ULONG_PTR)parameter >> 8), worker = (int)((ULONG_PTR)parameter & 0xff);
    Pool *p = &g_pools[pool];
    for (;;) {
        WaitForSingleObject(p->ready, INFINITE);
        EnterCriticalSection(&p->lock);
        int op = p->items[p->head++ % QUEUE];
        LeaveCriticalSection(&p->lock);
        if (op < 0) return 0;
        fx_handle_request(pool + 1, op, worker);
    }
}

FX int fx_object_create(int tag, void **where) {
    void *memory = VirtualAlloc(*where, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!memory) return 0;
    *(int *)memory = tag;
    *where = memory;
    return 1;
}

FX void fx_object_destroy(void *memory) { VirtualFree(memory, 0, MEM_RELEASE); }

FX int fx_handle_cycle(unsigned *first, unsigned *second) {
    HANDLE a = CreateEventA(NULL, TRUE, FALSE, NULL);
    *first = (unsigned)(ULONG_PTR)a;
    CloseHandle(a);
    HANDLE b = CreateEventA(NULL, TRUE, FALSE, NULL);
    *second = (unsigned)(ULONG_PTR)b;
    CloseHandle(b);
    return *first == *second;
}

FX int fx_module_cycle(void **first, void **second) {
    char path[MAX_PATH];
    typedef int (*value_fn)(int);
    GetModuleFileNameA(NULL, path, sizeof path);
    strcpy(strrchr(path, '\\') + 1, "interleave_mod.dll");
    HMODULE one = LoadLibraryA(path);
    if (!one) return -1;
    *first = (void *)one;
    value_fn call = (value_fn)GetProcAddress(one, "fx_mod_value");
    int a = call ? call(1) : -1;
    BYTE *base = (BYTE *)one;
    DWORD size = ((IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew))->OptionalHeader.SizeOfImage;
    FreeLibrary(one);
    VirtualAlloc(base, size, MEM_RESERVE, PAGE_NOACCESS); /* occupy the old base, so the reload must move */
    HMODULE two = LoadLibraryA(path);
    if (!two) return -2;
    *second = (void *)two;
    value_fn again = (value_fn)GetProcAddress(two, "fx_mod_value");
    int b = again ? again(1) : -1;
    FreeLibrary(two);
    VirtualFree(base, 0, MEM_RELEASE);
    return a == 88 && b == 88 ? 0 : -3;
}

FX int fx_spawn_child(DWORD *pid) {
    char exe[MAX_PATH], command[MAX_PATH + 16];
    STARTUPINFOA startup = { sizeof startup };
    PROCESS_INFORMATION info;
    GetModuleFileNameA(NULL, exe, sizeof exe);
    _snprintf(command, sizeof command, "\"%s\" --child", exe);
    if (!CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &info)) return -1;
    *pid = info.dwProcessId;
    WaitForSingleObject(info.hProcess, 10000);
    DWORD code = 99;
    GetExitCodeProcess(info.hProcess, &code);
    CloseHandle(info.hThread);
    CloseHandle(info.hProcess);
    return (int)code;
}

FX int fx_child_work(void) { return 5; }

int main(int argc, char **argv) {
    fx_arm_watchdog(60);
    if (fx_flag(argc, argv, "--child")) return fx_child_work() == 5 ? 0 : 1;
    g_all_done = CreateEventA(NULL, TRUE, FALSE, NULL);
    for (int p = 0; p < POOLS; ++p) {
        g_pools[p].number = p + 1;
        InitializeCriticalSection(&g_pools[p].lock);
        g_pools[p].ready = CreateSemaphoreA(NULL, 0, QUEUE, NULL);
        for (int w = 0; w < 2; ++w)
            g_pools[p].threads[w] = CreateThread(NULL, 0, worker_main, (LPVOID)(ULONG_PTR)((p << 8) | w), 0, NULL);
    }
    for (int i = 0; i < PER_POOL; ++i) {
        fx_submit(0, 1000 + i);
        fx_submit(1, 2000 + i);
        if (i == 3) fx_submit_dropped(1, 9999);
    }
    WaitForSingleObject(g_all_done, 20000);
    for (int p = 0; p < POOLS; ++p) {
        fx_submit(p, -1);
        fx_submit(p, -1);
        WaitForMultipleObjects(2, g_pools[p].threads, TRUE, 5000);
    }
    for (int p = 0; p < POOLS; ++p)
        for (int i = 0; i < PER_POOL; ++i) say("result op=%d value=%ld", (p + 1) * 1000 + i, g_results[p * PER_POOL + i]);
    say("completed=%ld dropped=1", g_completed);

    void *where = NULL, *again = NULL;
    fx_object_create(111, &where);
    void *first_address = where;
    fx_object_destroy(where);
    again = first_address; /* ask for the same address back */
    fx_object_create(222, &again);
    say("address_reused=%d tags=111,222", again == first_address);
    fx_object_destroy(again);

    unsigned h1, h2;
    int handle_reused = fx_handle_cycle(&h1, &h2);
    say("handle_reused=%d", handle_reused);

    void *m1 = NULL, *m2 = NULL;
    int module_status = fx_module_cycle(&m1, &m2);
    say("module_status=%d base_changed=%d", module_status, m1 != m2);

    DWORD pid1 = 0, pid2 = 0;
    int c1 = fx_spawn_child(&pid1), c2 = fx_spawn_child(&pid2);
    say("children=%d,%d pids_differ=%d", c1, c2, pid1 != pid2);
    say("done");
    return module_status == 0 && c1 == 0 && c2 == 0 ? 0 : 1;
}
