/* A save file an intervention modifies, and a value that does not round-trip (spec 15.8, docs/trace-fixtures.md).
   usage: persist.exe <work dir> save [--poke]
          persist.exe <work dir> load
   Save format (little-endian): "HPSV", u32 version 1, u32 count, then count records of 20 bytes:
   u32 id, u32 type, i32 value, char tag[8]. Defaults when no save exists: 1 hp=100, 2 flags=1 (bit 0: the feature
   is active), 3 gold=250, all type 1, and 4 boss tag "boss01" of type 2.
   save: loads the save if present (else the defaults), writes persist_before.dat (the persistent store before the
   session), optionally runs fx_instrument_poke(2, 0), the stand-in for an injected write that deactivates the
   feature, and writes persist_save.dat. The poke changes only record 2 (1 -> 0): the intervention-caused change,
   which survives removing the intervention because it is now in the file.
   load: a fresh process reads persist_save.dat. The loader only knows type 1; the type-2 tag of record 4 is dropped
   (it does not round-trip). */
#include "trace_common.h"

typedef struct Record { unsigned id, type; int value; char tag[8]; } Record;

static Record g_records[8];
static int g_count;

FX void fx_defaults(void) {
    Record defaults[4] = { { 1, 1, 100, "hp" }, { 2, 1, 1, "flags" }, { 3, 1, 250, "gold" }, { 4, 2, 0, "boss01" } };
    memcpy(g_records, defaults, sizeof defaults);
    g_count = 4;
}

FX int fx_write_store(const char *path) {
    unsigned char header[12] = { 'H', 'P', 'S', 'V', 1, 0, 0, 0, (unsigned char)g_count, 0, 0, 0 };
    FILE *file = fopen(path, "wb");
    if (!file) return 0;
    fwrite(header, 1, sizeof header, file);
    fwrite(g_records, sizeof(Record), (size_t)g_count, file);
    fclose(file);
    return 1;
}

/* only_known: the loader of the target understands type 1 only. */
FX int fx_read_store(const char *path, int only_known, int *dropped) {
    unsigned char header[12];
    Record record;
    FILE *file = fopen(path, "rb");
    g_count = 0;
    *dropped = 0;
    if (!file) return -1;
    if (fread(header, 1, sizeof header, file) != sizeof header || memcmp(header, "HPSV", 4) != 0) { fclose(file); return -2; }
    unsigned count = header[8];
    for (unsigned i = 0; i < count && fread(&record, sizeof record, 1, file) == 1; ++i) {
        if (only_known && record.type != 1) { say("dropped id=%u type=%u", record.id, record.type); ++*dropped; continue; }
        g_records[g_count++] = record;
    }
    fclose(file);
    return g_count;
}

/* The stand-in for the injected write: a temporary deactivation that is later saved by the target itself. */
FX void fx_instrument_poke(unsigned id, int value) {
    for (int i = 0; i < g_count; ++i)
        if (g_records[i].id == id) g_records[i].value = value;
}

static void show(const char *what) {
    for (int i = 0; i < g_count; ++i)
        say("%s id=%u type=%u value=%d tag=%s", what, g_records[i].id, g_records[i].type, g_records[i].value, g_records[i].tag);
}

int main(int argc, char **argv) {
    char save[MAX_PATH], before[MAX_PATH];
    int dropped = 0;
    if (argc < 3) { fprintf(stderr, "usage: persist <dir> save|load [--poke]\n"); return 2; }
    fx_arm_watchdog(20);
    CreateDirectoryA(argv[1], NULL);
    fx_path(save, sizeof save, argv[1], "persist_save.dat");
    fx_path(before, sizeof before, argv[1], "persist_before.dat");
    if (strcmp(argv[2], "load") == 0) {
        int loaded = fx_read_store(save, 1, &dropped);
        if (loaded < 0) return 3;
        show("loaded");
        say("loaded_count=%d dropped=%d", loaded, dropped);
        return 0;
    }
    if (fx_read_store(save, 0, &dropped) < 0) fx_defaults();
    if (!fx_write_store(before)) return 4;
    if (fx_flag(argc, argv, "--poke")) fx_instrument_poke(2, 0);
    if (!fx_write_store(save)) return 5;
    show("saved");
    say("saved_count=%d poke=%d", g_count, fx_flag(argc, argv, "--poke"));
    return 0;
}
