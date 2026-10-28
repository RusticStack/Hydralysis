/* A program whose answers are known, for the analysis and runtime checks
   (docs/verification-fixtures.md). Built for x64 and x86 by build_fixtures.py.

   - value flow: fx_flow stores 0x2A into Config.limit through fx_relay -> fx_store
     and reads it back with fx_read;
   - field writers: exactly three functions write Config.limit (fx_store, fx_reset,
     fx_clamp); Pair.second sits at the same offset on x86 and is written by fx_pair;
   - a live patch: at start main writes a jmp from fx_hooked to fx_detour;
   - a float per frame: fx_tick(Config*, float dt) once per loop;
   - an exported function, fx_exported(int), called once per loop with the frame number: the export-name hook
     check hooks it by name, from the file's export table. */
#include <windows.h>
#include <stdio.h>

#define FX __declspec(noinline)

typedef struct Config { int mode; int limit; float speed; } Config;
typedef struct Holder { int tag; Config *config; } Holder;
typedef struct Pair { void *first; int second; } Pair;

volatile int g_sink;
Config g_config = { 2, 0, 0.0f };
Pair g_pair;

FX void fx_store(Config *config, int value) { config->limit = value; }
FX void fx_relay(Holder *holder, int value) { fx_store(holder->config, value); }
FX int fx_read(Holder *holder) { return holder->config->limit; }
FX int fx_flow(void) {
    Config config = { 1, 0, 0.0f };
    Holder holder = { 7, &config };
    fx_relay(&holder, 0x2A);
    return fx_read(&holder);
}

FX void fx_reset(Config *config) { config->limit = 0; }
FX void fx_clamp(Config *config) { if (config->limit > 100) config->limit = 100; else config->limit += 1; }
FX void fx_pair(Pair *pair, int value) { pair->second = value; }

FX int fx_hooked(int value) { return value * 3 + 1; }
FX int fx_detour(int value) { return value * 3 + 2; }

FX float fx_tick(Config *config, float dt) { config->speed += dt; return config->speed; }

__declspec(dllexport) FX int fx_exported(int value) { return value * 5 + 3; }

static void install_detour(void) {
    unsigned char *site = (unsigned char *)fx_hooked;
    if (site[0] == 0xE9) site += 5 + *(int *)(site + 1);  /* an incremental-link thunk */
    unsigned char *target = (unsigned char *)fx_detour;
    if (target[0] == 0xE9) target += 5 + *(int *)(target + 1);
    DWORD old;
    VirtualProtect(site, 5, PAGE_EXECUTE_READWRITE, &old);
    site[0] = 0xE9;
    *(int *)(site + 1) = (int)(target - (site + 5));
    VirtualProtect(site, 5, old, &old);
    FlushInstructionCache(GetCurrentProcess(), site, 5);
}

int main(int argc, char **argv) {
    install_detour();
    /* argv[1]: a stop file; the loop ends when it exists (or after 10 minutes). */
    for (int frame = 0; frame < 12000; ++frame) {
        if (argc > 1 && GetFileAttributesA(argv[1]) != INVALID_FILE_ATTRIBUTES) break;
        g_sink = fx_flow();
        fx_reset(&g_config);
        fx_store(&g_config, frame % 150);
        fx_clamp(&g_config);
        fx_pair(&g_pair, frame);
        g_sink += fx_hooked(frame);
        fx_tick(&g_config, 0.25f + (frame % 4) * 0.125f);
        g_sink += fx_exported(frame);
        Sleep(50);
    }
    return 0;
}
