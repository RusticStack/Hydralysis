/* M1 resources and precedence, M2 two-config diff (docs/trace-fixtures.md).
   usage: trace_app.exe <work dir> <A|B>
   Stages two DLLs, writes and reads back a config file and a data file (and an extra file under config B),
   sets and reads a registry value under HKCU\Software\HydraTraceFixture, then loads trace_plugin.dll by bare name.
   Config A puts plug\dir_a in the DLL directory and plug\dir_b in PATH (dir_a wins, plugin id 1); config B swaps
   them (dir_b wins, id 2): the same call, a different precedence. */
#include "trace_common.h"
#pragma comment(lib, "advapi32.lib")

static char g_work[MAX_PATH];

FX static int make_dirs(void) {
    char path[MAX_PATH];
    CreateDirectoryA(g_work, NULL);
    fx_path(path, sizeof path, g_work, "plug");
    CreateDirectoryA(path, NULL);
    fx_path(path, sizeof path, g_work, "plug\\dir_a");
    CreateDirectoryA(path, NULL);
    fx_path(path, sizeof path, g_work, "plug\\dir_b");
    return CreateDirectoryA(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
}

FX int fx_write_file(const char *path, const void *data, DWORD size) {
    HANDLE file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written = 0;
    if (file == INVALID_HANDLE_VALUE) return 0;
    WriteFile(file, data, size, &written, NULL);
    CloseHandle(file);
    return written == size;
}

FX int fx_read_file(const char *path, void *data, DWORD size) {
    HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD got = 0;
    if (file == INVALID_HANDLE_VALUE) return -1;
    ReadFile(file, data, size, &got, NULL);
    CloseHandle(file);
    return (int)got;
}

FX static int stage_plugin(const char *source_name, const char *directory) {
    char exe[MAX_PATH], from[MAX_PATH], to[MAX_PATH];
    GetModuleFileNameA(NULL, exe, sizeof exe);
    *strrchr(exe, '\\') = 0;
    fx_path(from, sizeof from, exe, source_name);
    _snprintf(to, sizeof to, "%s\\plug\\%s\\trace_plugin.dll", g_work, directory);
    return CopyFileA(from, to, FALSE);
}

/* The config toggle: the value read here decides the precedence, the extra file and the registry value. */
FX int fx_read_config(const char *name, char *precedence, int *extra) {
    char path[MAX_PATH], text[128] = { 0 };
    const char *body = strcmp(name, "B") == 0 ? "precedence=dir_b\nextra=1\n" : "precedence=dir_a\nextra=0\n";
    fx_path(path, sizeof path, g_work, "trace_app.cfg");
    if (!fx_write_file(path, body, (DWORD)strlen(body))) return 0;
    if (fx_read_file(path, text, sizeof text - 1) <= 0) return 0;
    strcpy(precedence, strstr(text, "dir_b") ? "dir_b" : "dir_a");
    *extra = strstr(text, "extra=1") != NULL;
    return 1;
}

FX int fx_registry_roundtrip(const char *mode, char *back, DWORD size) {
    HKEY key;
    DWORD type = 0, got = size;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\HydraTraceFixture", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL)) return 0;
    RegSetValueExA(key, "Mode", 0, REG_SZ, (const BYTE *)mode, (DWORD)strlen(mode) + 1);
    back[0] = 0;
    RegQueryValueExA(key, "Mode", NULL, &type, (BYTE *)back, &got);
    RegCloseKey(key);
    return type == REG_SZ;
}

FX void fx_registry_cleanup(void) {
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\HydraTraceFixture");
}

/* The shadow: the same bare name resolves in one of two directories. */
FX int fx_load_plugin(const char *winner, const char *loser, char *loaded_dir) {
    char win_path[MAX_PATH], lose_path[MAX_PATH], full[MAX_PATH * 2], module_path[MAX_PATH];
    typedef int (*plugin_id_fn)(void);
    fx_path(win_path, sizeof win_path, g_work, "plug");
    strcat(win_path, "\\");
    strcat(win_path, winner);
    fx_path(lose_path, sizeof lose_path, g_work, "plug");
    strcat(lose_path, "\\");
    strcat(lose_path, loser);
    SetDllDirectoryA(win_path);
    _snprintf(full, sizeof full, "%s;%s", lose_path, getenv("PATH") ? getenv("PATH") : "");
    full[sizeof full - 1] = 0;
    SetEnvironmentVariableA("PATH", full);
    HMODULE module = LoadLibraryA("trace_plugin.dll");
    if (!module) return -1;
    GetModuleFileNameA(module, module_path, sizeof module_path);
    char *plug = strstr(module_path, "plug\\");
    strcpy(loaded_dir, plug ? plug + 5 : module_path);
    char *slash = strchr(loaded_dir, '\\');
    if (slash) *slash = 0;
    plugin_id_fn id = (plugin_id_fn)GetProcAddress(module, "fx_plugin_id");
    int value = id ? id() : -2;
    FreeLibrary(module);
    return value;
}

int main(int argc, char **argv) {
    char precedence[16], loaded[64], back[32], path[MAX_PATH], data[32], again[32];
    int extra = 0;
    if (argc < 3) { fprintf(stderr, "usage: trace_app <work dir> <A|B>\n"); return 2; }
    fx_arm_watchdog(30);
    strncpy(g_work, argv[1], sizeof g_work - 1);
    const char *config = argv[2];
    if (!make_dirs() || !stage_plugin("trace_plugin_1.dll", "dir_a") || !stage_plugin("trace_plugin_2.dll", "dir_b")) return 3;
    if (!fx_read_config(config, precedence, &extra)) return 4;
    say("config=%s", config);
    say("precedence=%s", precedence);
    for (int i = 0; i < 32; ++i) data[i] = (char)('a' + i % 26);
    fx_path(path, sizeof path, g_work, "trace_app.data");
    int data_ok = fx_write_file(path, data, 32) && fx_read_file(path, again, 32) == 32 && memcmp(data, again, 32) == 0;
    say("data_ok=%d", data_ok);
    if (extra) {
        fx_path(path, sizeof path, g_work, "trace_app.extra");
        int extra_ok = fx_write_file(path, "extra-config-b", 14) && fx_read_file(path, again, 14) == 14;
        say("extra_read=%d", extra_ok);
    } else {
        say("extra_read=0");
    }
    int registry_ok = fx_registry_roundtrip(config, back, sizeof back);
    say("registry_mode=%s ok=%d", back, registry_ok);
    int dir_b_wins = strcmp(precedence, "dir_b") == 0;
    int id = fx_load_plugin(dir_b_wins ? "dir_b" : "dir_a", dir_b_wins ? "dir_a" : "dir_b", loaded);
    say("plugin_id=%d", id);
    say("plugin_dir=%s", loaded);
    fx_registry_cleanup();
    say("done");
    return data_ok && registry_ok && id > 0 ? 0 : 5;
}
