/* A small script VM with a native binding table (spec 15.7, docs/trace-fixtures.md).
   usage: minivm.exe
   Twelve natives are visible to the script: ten come from the static table g_native_table (copied into the
   registry by fx_vm_load_table) and two are registered by calls, fx_vm_register("dist2", ...) and
   fx_vm_register("select", ...). The script is a list of lines "name arg ..."; fx_vm_run_line looks the name up in
   the registry (fx_vm_find), collects the declared number of arguments and calls fx_vm_dispatch, which calls the
   native through its pointer: script name -> native address -> parameter count. */
#include "trace_common.h"

typedef int (*native_fn)(const int *args);
typedef struct Native { const char *name; native_fn fn; int nargs; } Native;

FX int fx_nat_add(const int *a) { return a[0] + a[1]; }
FX int fx_nat_sub(const int *a) { return a[0] - a[1]; }
FX int fx_nat_mul(const int *a) { return a[0] * a[1]; }
FX int fx_nat_neg(const int *a) { return -a[0]; }
FX int fx_nat_min(const int *a) { return a[0] < a[1] ? a[0] : a[1]; }
FX int fx_nat_max(const int *a) { return a[0] > a[1] ? a[0] : a[1]; }
FX int fx_nat_clamp(const int *a) { return a[0] < a[1] ? a[1] : a[0] > a[2] ? a[2] : a[0]; }
FX int fx_nat_abs(const int *a) { return a[0] < 0 ? -a[0] : a[0]; }
FX int fx_nat_sq(const int *a) { return a[0] * a[0]; }
FX int fx_nat_avg3(const int *a) { return (a[0] + a[1] + a[2]) / 3; }
FX int fx_nat_dist2(const int *a) { int dx = a[2] - a[0], dy = a[3] - a[1]; return dx * dx + dy * dy; }
FX int fx_nat_select(const int *a) { return a[0] ? a[1] : a[2]; }

/* The table registration: ten rows {script name, native pointer, parameter count}. */
const Native g_native_table[10] = {
    { "add", fx_nat_add, 2 }, { "sub", fx_nat_sub, 2 }, { "mul", fx_nat_mul, 2 }, { "neg", fx_nat_neg, 1 },
    { "min", fx_nat_min, 2 }, { "max", fx_nat_max, 2 }, { "clamp", fx_nat_clamp, 3 }, { "abs", fx_nat_abs, 1 },
    { "sq", fx_nat_sq, 1 }, { "avg3", fx_nat_avg3, 3 },
};

static Native g_registry[16];
static int g_registered;

FX int fx_vm_register(const char *name, native_fn fn, int nargs) {
    g_registry[g_registered].name = name;
    g_registry[g_registered].fn = fn;
    g_registry[g_registered].nargs = nargs;
    return g_registered++;
}

FX void fx_vm_load_table(const Native *table, int count) {
    for (int i = 0; i < count; ++i) fx_vm_register(table[i].name, table[i].fn, table[i].nargs);
}

FX const Native *fx_vm_find(const char *name) {
    for (int i = 0; i < g_registered; ++i)
        if (strcmp(g_registry[i].name, name) == 0) return &g_registry[i];
    return NULL;
}

FX int fx_vm_dispatch(const Native *native, const int *args) { return native->fn(args); }

FX int fx_vm_run_line(const char *line) {
    char text[64], *token, *context = NULL;
    int args[8] = { 0 }, count = 0;
    strncpy(text, line, sizeof text - 1);
    text[sizeof text - 1] = 0;
    token = strtok_s(text, " ", &context);
    const Native *native = token ? fx_vm_find(token) : NULL;
    if (!native) { say("call unknown=%s", line); return 0; }
    while ((token = strtok_s(NULL, " ", &context)) != NULL && count < 8) args[count++] = atoi(token);
    int result = fx_vm_dispatch(native, args);
    say("call name=%s args=%d result=%d", native->name, native->nargs, result);
    return count == native->nargs;
}

static const char *const g_script[12] = {
    "add 2 3", "sub 10 4", "mul 6 7", "neg 5", "min 9 3", "max 9 3", "clamp 15 0 10", "abs -8", "sq 12", "avg3 3 6 9",
    "dist2 0 0 3 4", "select 1 111 222",
};

int main(void) {
    int good = 0;
    fx_arm_watchdog(20);
    fx_vm_load_table(g_native_table, 10);
    fx_vm_register("dist2", fx_nat_dist2, 4);
    fx_vm_register("select", fx_nat_select, 3);
    say("registered=%d", g_registered);
    for (int i = 0; i < 12; ++i) good += fx_vm_run_line(g_script[i]);
    say("script_ok=%d", good);
    return good == 12 ? 0 : 1;
}
