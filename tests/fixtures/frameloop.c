/* A real-time loop: frames, stages, thread roles, a write that may not survive (docs/trace-fixtures.md,
   spec 15.2, 15.3 and 14.8).
   usage: frameloop.exe [--frames=60] [--sleep-ms=0] [--callback-on=main|worker] [--ours-stage=update|render]
                        [--no-overwrite] [--survive-every=10] [--skip-marker=input|update|render]
   Each frame: fx_frame_begin(frame); stage 1 input (fx_stage_input), stage 2 update (fx_stage_update), stage 3
   render (fx_stage_render); fx_frame_end(frame). Every stage opens with fx_phase_begin(stage number) unless
   --skip-marker names it. A two-thread job pool (thread start fx_pool_thread) runs fx_job_physics every frame.
   fx_job_callback(frame) is the callback: on the main thread by default, on a pool thread with
   --callback-on=worker.
   The field is g_entity.value. Our write fx_ours_write (value 5000+frame) is in update by default, or in render
   after the consumer with --ours-stage=render (one stage too late). The host's own component fx_host_overwrite
   (value 9000+frame) runs at the start of render on every frame except frame % survive-every == survive-every-1,
   or never with --no-overwrite. The consumer fx_consume runs in render and reads the field. */
#include "trace_common.h"

typedef struct Entity { int tag; int value; int writer; int write_frame; } Entity;

__declspec(dllexport) Entity g_entity = { 77, 0, 0, -1 };
static volatile LONG g_callback_sum, g_physics_sum, g_input;
static long g_consumer_sum;
static int g_survived, g_overwritten, g_before_write;
static int g_frame = -1;
static volatile int g_frames_ended, g_last_stage;
static HANDLE g_jobs, g_job_done, g_pool[2];
static volatile LONG g_job_frame = -1, g_job_kind, g_pool_stop;

FX void fx_frame_begin(int frame) { g_frame = frame; }
FX void fx_frame_end(int frame) { g_frames_ended = frame + 1; }
FX void fx_phase_begin(int stage) { g_last_stage = stage; }

FX int fx_job_callback(int frame) { InterlockedAdd(&g_callback_sum, frame); return frame; }
FX int fx_job_physics(int frame) { InterlockedAdd(&g_physics_sum, frame * 2); return frame * 2; }

FX void fx_stage_input(int frame) { InterlockedExchange(&g_input, frame * 3); }

FX void fx_ours_write(int frame) {
    g_entity.value = 5000 + frame;
    g_entity.writer = 1;
    g_entity.write_frame = frame;
}

FX void fx_host_overwrite(int frame) {
    g_entity.value = 9000 + frame;
    g_entity.writer = 2;
    g_entity.write_frame = frame;
}

FX int fx_consume(int frame) {
    int seen = g_entity.value;
    if (g_entity.write_frame == frame && g_entity.writer == 1) ++g_survived;
    else if (g_entity.write_frame == frame && g_entity.writer == 2) ++g_overwritten;
    else ++g_before_write;
    g_consumer_sum += seen;
    return seen;
}

/* One job at a time, handed to the pool and awaited, so the frame stays deterministic. */
static DWORD WINAPI fx_pool_thread(LPVOID unused) {
    (void)unused;
    for (;;) {
        WaitForSingleObject(g_jobs, INFINITE);
        if (g_pool_stop) return 0;
        if (g_job_kind == 1) fx_job_callback(g_job_frame); else fx_job_physics(g_job_frame);
        SetEvent(g_job_done);
    }
}

static void run_on_pool(int kind, int frame) {
    g_job_kind = kind;
    g_job_frame = frame;
    ReleaseSemaphore(g_jobs, 1, NULL);
    WaitForSingleObject(g_job_done, INFINITE);
}

FX void fx_stage_update(int frame, int callback_on_worker, int ours_in_render) {
    run_on_pool(0, frame);
    if (callback_on_worker) run_on_pool(1, frame); else fx_job_callback(frame);
    if (!ours_in_render) fx_ours_write(frame);
}

FX void fx_stage_render(int frame, int overwrite, int ours_in_render) {
    if (overwrite) fx_host_overwrite(frame);
    fx_consume(frame);
    if (ours_in_render) fx_ours_write(frame);
}

int main(int argc, char **argv) {
    int frames = fx_arg_int(argc, argv, "--frames=", 60), sleep_ms = fx_arg_int(argc, argv, "--sleep-ms=", 0);
    int every = fx_arg_int(argc, argv, "--survive-every=", 10);
    const char *callback = fx_arg(argc, argv, "--callback-on="), *ours = fx_arg(argc, argv, "--ours-stage=");
    const char *skip = fx_arg(argc, argv, "--skip-marker=");
    int on_worker = callback && strcmp(callback, "worker") == 0, ours_in_render = ours && strcmp(ours, "render") == 0;
    int no_overwrite = fx_flag(argc, argv, "--no-overwrite");
    fx_arm_watchdog(120);
    g_jobs = CreateSemaphoreA(NULL, 0, 2, NULL);
    g_job_done = CreateEventA(NULL, FALSE, FALSE, NULL);
    for (int i = 0; i < 2; ++i) g_pool[i] = CreateThread(NULL, 0, fx_pool_thread, NULL, 0, NULL);
    /* two pool threads share one semaphore; only one job is ever in flight */
    for (int frame = 0; frame < frames; ++frame) {
        fx_frame_begin(frame);
        if (!skip || strcmp(skip, "input")) fx_phase_begin(1);
        fx_stage_input(frame);
        if (!skip || strcmp(skip, "update")) fx_phase_begin(2);
        fx_stage_update(frame, on_worker, ours_in_render);
        if (!skip || strcmp(skip, "render")) fx_phase_begin(3);
        fx_stage_render(frame, !no_overwrite && frame % every != every - 1, ours_in_render);
        fx_frame_end(frame);
        if (sleep_ms) Sleep(sleep_ms);
    }
    g_pool_stop = 1;
    ReleaseSemaphore(g_jobs, 1, NULL);
    ReleaseSemaphore(g_jobs, 1, NULL);
    WaitForMultipleObjects(2, g_pool, TRUE, 5000);
    say("frames=%d", frames);
    say("callback_sum=%ld physics_sum=%ld", g_callback_sum, g_physics_sum);
    say("consumer_sum=%ld", g_consumer_sum);
    say("verdicts survived=%d overwritten=%d read_before_write=%d", g_survived, g_overwritten, g_before_write);
    return 0;
}
