/* The owner of a replicated value (spec 15.5, docs/trace-fixtures.md).
   usage: replica_a.exe <tag> <log file>      (start before replica_b.exe <tag> <log> ...)
   Object 1 moves: its value at tick N is N*7, published by fx_truth_publish every 20 ms for 200 ticks and sent to the
   replica, except ticks 60..159 (a 2 s outage: nothing is sent). Object 2 exists on the owner from tick 30
   (fx_truth_create) and is never replicated. Three SYNC markers are sent first, before any value, so the pair can
   calibrate its clock offset. The log is JSON lines: side owner, kind truth|sync|create|end, t_ms on the owner
   clock (milliseconds since the first SYNC). */
#include "replica_common.h"

static FILE *g_log;
static HANDLE g_pipe = INVALID_HANDLE_VALUE;
static double g_origin_ms;

static double clock_ms(void) { return fx_now_ms() - g_origin_ms; }

FX void fx_truth_publish(int obj, int seq, int value) {
    fprintf(g_log, "{\"side\":\"owner\",\"kind\":\"truth\",\"t_ms\":%.3f,\"obj\":%d,\"seq\":%d,\"value\":%d}\n",
            clock_ms(), obj, seq, value);
}

FX void fx_truth_create(int obj, int seq) {
    fprintf(g_log, "{\"side\":\"owner\",\"kind\":\"create\",\"t_ms\":%.3f,\"obj\":%d,\"seq\":%d}\n", clock_ms(), obj, seq);
}

FX int fx_send_message(int kind, int obj, int seq, int value) {
    Message message = { kind, obj, seq, value, clock_ms() };
    DWORD written = 0;
    return WriteFile(g_pipe, &message, sizeof message, &written, NULL) && written == sizeof message;
}

FX void fx_send_sync(int n) {
    fprintf(g_log, "{\"side\":\"owner\",\"kind\":\"sync\",\"t_ms\":%.3f,\"n\":%d}\n", clock_ms(), n);
    fx_send_message(MSG_SYNC, 0, n, 0);
}

int main(int argc, char **argv) {
    char name[128];
    if (argc < 3) { fprintf(stderr, "usage: replica_a <tag> <log>\n"); return 2; }
    fx_arm_watchdog(40);
    g_log = fopen(argv[2], "wb");
    if (!g_log) return 3;
    pipe_name(name, sizeof name, argv[1]);
    g_pipe = CreateNamedPipeA(name, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 1 << 16, 1 << 16, 0, NULL);
    if (g_pipe == INVALID_HANDLE_VALUE) return 4;
    say("owner listening");
    if (!ConnectNamedPipe(g_pipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) return 5;
    g_origin_ms = fx_now_ms();
    for (int n = 0; n < 3; ++n) { fx_send_sync(n); Sleep(10); }
    int sent = 0, skipped = 0;
    for (int seq = 0; seq < STEPS; ++seq) {
        double due = 40.0 + (seq + 1) * (double)TICK_MS;
        while (clock_ms() < due) Sleep(1);
        if (seq == OWNER_ONLY_FROM) fx_truth_create(2, seq);
        fx_truth_publish(1, seq, MOVING_VALUE(seq));
        if (seq >= OUTAGE_FROM && seq < OUTAGE_TO) ++skipped;
        else { fx_send_message(MSG_VALUE, 1, seq, MOVING_VALUE(seq)); ++sent; }
    }
    fx_send_message(MSG_END, 0, STEPS, 0);
    fprintf(g_log, "{\"side\":\"owner\",\"kind\":\"end\",\"t_ms\":%.3f}\n", clock_ms());
    fclose(g_log);
    FlushFileBuffers(g_pipe);
    CloseHandle(g_pipe);
    say("owner sent=%d skipped=%d objects=2", sent, skipped);
    return 0;
}
