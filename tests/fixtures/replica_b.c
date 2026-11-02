/* The replica of a value owned by replica_a.exe (spec 15.5, docs/trace-fixtures.md).
   usage: replica_b.exe <tag> <log file> [clock offset ms, default 250]
   Connects to the owner pipe, applies each value message DELAY_MS (100 ms) after receiving it (fx_mirror_apply),
   and ticks every 20 ms; a tick with no applied value in the last 60 ms is logged as an extrapolated mirror
   (fx_mirror_extrapolate). Its log timestamps are on its own clock: the monotonic clock since connecting plus the
   offset argument, so the pair has a known offset to recover from the SYNC markers (replica receive time minus the
   owner send time = offset + transport latency, a few ms). JSON lines: side replica,
   kind mirror|extrapolated|sync|end. */
#include "replica_common.h"

static FILE *g_log;
static double g_origin_ms, g_offset_ms;

static double clock_ms(void) { return fx_now_ms() - g_origin_ms + g_offset_ms; }

FX void fx_mirror_apply(int obj, int seq, int value) {
    fprintf(g_log, "{\"side\":\"replica\",\"kind\":\"mirror\",\"t_ms\":%.3f,\"obj\":%d,\"seq\":%d,\"value\":%d}\n",
            clock_ms(), obj, seq, value);
}

FX void fx_mirror_extrapolate(int obj, int last_seq, int value) {
    fprintf(g_log, "{\"side\":\"replica\",\"kind\":\"extrapolated\",\"t_ms\":%.3f,\"obj\":%d,\"seq\":%d,\"value\":%d}\n",
            clock_ms(), obj, last_seq, value);
}

FX void fx_receive_sync(int n, double owner_sent_ms) {
    fprintf(g_log, "{\"side\":\"replica\",\"kind\":\"sync\",\"t_ms\":%.3f,\"n\":%d,\"owner_sent_ms\":%.3f}\n",
            clock_ms(), n, owner_sent_ms);
}

typedef struct Pending { Message message; double apply_at; } Pending;

int main(int argc, char **argv) {
    char name[128];
    static Pending pending[512];
    int head = 0, tail = 0, ended = 0, applied = 0, extrapolated = 0, last_seq = -1, last_value = 0;
    double last_applied_ms = -1000;
    if (argc < 3) { fprintf(stderr, "usage: replica_b <tag> <log> [offset]\n"); return 2; }
    fx_arm_watchdog(40);
    g_offset_ms = argc > 3 ? atof(argv[3]) : 250.0;
    g_log = fopen(argv[2], "wb");
    if (!g_log) return 3;
    pipe_name(name, sizeof name, argv[1]);
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int tries = 0; tries < 400 && pipe == INVALID_HANDLE_VALUE; ++tries) {
        pipe = CreateFileA(name, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (pipe == INVALID_HANDLE_VALUE) Sleep(25);
    }
    if (pipe == INVALID_HANDLE_VALUE) return 4;
    g_origin_ms = fx_now_ms();
    double next_tick = 0;
    while (!ended || head != tail) {
        DWORD available = 0;
        while (!ended && PeekNamedPipe(pipe, NULL, 0, NULL, &available, NULL) && available >= sizeof(Message)) {
            Message message;
            DWORD got = 0;
            if (!ReadFile(pipe, &message, sizeof message, &got, NULL) || got != sizeof message) { ended = 1; break; }
            double now = fx_now_ms() - g_origin_ms;
            if (message.kind == MSG_SYNC) fx_receive_sync(message.seq, message.sent_ms);
            else if (message.kind == MSG_END) ended = 1;
            else { pending[tail % 512].message = message; pending[tail % 512].apply_at = now + DELAY_MS; ++tail; }
        }
        if (!ended && !PeekNamedPipe(pipe, NULL, 0, NULL, &available, NULL)) ended = 1; /* broken pipe: the owner is gone */
        double now = fx_now_ms() - g_origin_ms;
        while (head != tail && pending[head % 512].apply_at <= now) {
            Message *message = &pending[head % 512].message;
            fx_mirror_apply(message->obj, message->seq, message->value);
            last_seq = message->seq; last_value = message->value; last_applied_ms = now; ++applied; ++head;
        }
        if (now >= next_tick) {
            next_tick += TICK_MS;
            if (last_seq >= 0 && now - last_applied_ms > 60 && !ended) {
                fx_mirror_extrapolate(1, last_seq, last_value + (int)((now - last_applied_ms) / TICK_MS) * 7);
                ++extrapolated;
            }
        }
        Sleep(1);
    }
    fprintf(g_log, "{\"side\":\"replica\",\"kind\":\"end\",\"t_ms\":%.3f}\n", clock_ms());
    fclose(g_log);
    say("replica applied=%d extrapolated=%d", applied, extrapolated > 0);
    return 0;
}
