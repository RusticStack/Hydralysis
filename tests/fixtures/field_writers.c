/* Who writes Thing.level? (spec 14.4, docs/trace-fixtures.md)
   usage: field_writers.exe [--frames=20]
   struct Thing { int tag; int level; int other; }  - the selected field is g_thing.level (offset 4).
   Static candidates (stores at offset 4 of a Thing):
     fx_set_level(t, v)   called every frame                     -> observed
     fx_bump_level(t)     only called when the program is started with --bump (never in the default run) -> candidate, never executed
   Another site that writes the selected object without a store at offset 4: fx_reset_thing copies a whole fresh Thing
   over it (the compiler emits wide moves, not a `level` store), every 5th frame -> observed, not a static candidate.
   An alias: fx_alias_write(int *p, int v) writes *p. fx_use_alias passes it &g_thing.level every 4th frame. The callee is
   not instrumented, so the write is not observed and the static scan cannot attribute it to the field -> unresolved. */
#include "trace_common.h"

typedef struct Thing { int tag; int level; int other; } Thing;

Thing g_thing = { 1, 0, 0 };
static volatile int g_sink;

FX void fx_set_level(Thing *t, int value) { t->level = value; g_sink += value; }
FX void fx_bump_level(Thing *t) { t->level = t->level + 1; g_sink += 3; }
FX void fx_reset_thing(Thing *t, int tag) {
    Thing fresh;
    fresh.tag = tag;
    fresh.level = 0;
    fresh.other = tag * 2;
    *t = fresh;
}
FX void fx_alias_write(int *p, int value) { *p = value; g_sink += 5; }
FX void fx_use_alias(Thing *t, int value) { fx_alias_write(&t->level, value); g_sink += 7; }
FX void fx_note_frame(int frame) { g_sink += frame; }

int main(int argc, char **argv) {
    int frames = fx_arg_int(argc, argv, "--frames=", 20);
    int bump = fx_flag(argc, argv, "--bump");
    fx_arm_watchdog(60);
    for (int frame = 0; frame < frames; ++frame) {
        fx_note_frame(frame);
        fx_set_level(&g_thing, 100 + frame);
        if (frame % 5 == 4) fx_reset_thing(&g_thing, frame);
        if (frame % 4 == 3) fx_use_alias(&g_thing, 700 + frame);
        if (bump) fx_bump_level(&g_thing);
    }
    say("frames=%d level=%d tag=%d other=%d", frames, g_thing.level, g_thing.tag, g_thing.other);
    return 0;
}
