"""Writes tests/fixtures/expected/<fixture>.json: the machine-readable expected answers of the semantic-trace fixtures.

Every number here comes from an independent model in this file (struct packing, FNV-1a, a frame-loop simulation), never
from a run of the fixture; tests/test_trace_fixtures.py then checks that the built programs agree with it. The files are
committed; rerun this script after changing a fixture and review the diff.

usage: python tests/fixtures/make_trace_expected.py

File layout (all fixtures):
  fixture, spec, sources, outputs (built by build_fixtures.py, see TRACE_GROUPS)
  functions   role -> fx_ function name in the linker map (the names acceptance tests look up in trace_manifest.json)
  runs        what the smoke test executes. Per run: args ({work} is a fresh work dir), max_seconds, exit_code,
              stdout_lines (the exact stdout), stdout_regex (lines that must exist, any order), files (checked
              after the run: {"text": ...} | {"hex": ...} | {"prefix_hex": ...} | {"exists": true})
              A run may name a "companion" started first (the owner of the replica pair).
  answers     the facts an acceptance test compares a trace or an analysis result with (events, relations, verdicts)
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import gen_fnv_names

OUT = Path(__file__).resolve().parent / "expected"


def write(name: str, document: dict) -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / (name + ".json")).write_text(json.dumps(document, indent=1) + "\n", newline="\n")


def lines(*items: str) -> list[str]:
    return list(items)


# --- trace_app ---------------------------------------------------------------------------------------------------------

def trace_app() -> None:
    data = "".join(chr(ord("a") + i % 26) for i in range(32))

    def run(config: str) -> dict:
        other = "dir_b" if config == "A" else "dir_a"
        winner = "dir_a" if config == "A" else "dir_b"
        out = ["FX config=" + config, "FX precedence=" + winner, "FX data_ok=1", "FX extra_read=" + ("1" if config == "B" else "0"),
               "FX registry_mode=%s ok=1" % config, "FX plugin_id=%d" % (1 if config == "A" else 2), "FX plugin_dir=" + winner, "FX done"]
        files = {"trace_app.cfg": {"text": "precedence=%s\nextra=%d\n" % (winner, 1 if config == "B" else 0)},
                 "trace_app.data": {"text": data},
                 "plug/dir_a/trace_plugin.dll": {"exists": True}, "plug/dir_b/trace_plugin.dll": {"exists": True}}
        if config == "B":
            files["trace_app.extra"] = {"text": "extra-config-b"}
        return {"id": "config_" + config, "program": "trace_app.exe", "args": ["{work}", config], "max_seconds": 20,
                "exit_code": 0, "stdout_lines": out, "files": files, "loser_dir": other}

    write("trace_app", {
        "fixture": "trace_app", "spec": ["M1 resources and precedence", "M2 two-config diff"],
        "sources": ["trace_app.c", "trace_plugin.c", "trace_common.h"],
        "outputs": ["trace_app.exe", "trace_plugin_1.dll", "trace_plugin_2.dll"],
        "functions": {"write_file": "fx_write_file", "read_file": "fx_read_file", "read_config": "fx_read_config",
                      "registry": "fx_registry_roundtrip", "registry_cleanup": "fx_registry_cleanup",
                      "load_plugin": "fx_load_plugin", "plugin_id_export": "fx_plugin_id"},
        "runs": [run("A"), run("B")],
        "answers": {
            "resources": {
                "files": ["trace_app.cfg (create, write 24/25 bytes, read back)", "trace_app.data (create, write 32, read 32)",
                          "trace_app.extra (config B only: create, write 14, read 14)",
                          "plug/dir_a/trace_plugin.dll and plug/dir_b/trace_plugin.dll (copied from trace_plugin_1/2.dll)"],
                "registry": {"key": "HKCU\\Software\\HydraTraceFixture", "value": "Mode", "type": "REG_SZ",
                             "operations": ["create key", "set Mode", "query Mode", "delete key"]},
                "data_bytes": data,
            },
            "dll_search_order": {
                "call": "LoadLibraryA(\"trace_plugin.dll\") in fx_load_plugin",
                "config_A": {"set_dll_directory": "plug/dir_a", "path_entry": "plug/dir_b", "loaded_from": "plug/dir_a", "plugin_id": 1,
                             "shadowed": "plug/dir_b/trace_plugin.dll (exists, never loaded)"},
                "config_B": {"set_dll_directory": "plug/dir_b", "path_entry": "plug/dir_a", "loaded_from": "plug/dir_b", "plugin_id": 2,
                             "shadowed": "plug/dir_a/trace_plugin.dll (exists, never loaded)"},
                "rule": "the SetDllDirectory directory is searched before PATH, so the same bare name resolves to different files",
            },
            "two_config_diff": {
                "differs": ["trace_app.cfg content", "trace_app.extra exists only in B", "registry value Mode A -> B",
                            "module loaded from dir_a -> dir_b", "fx_plugin_id result 1 -> 2"],
                "same": ["trace_app.data content and its write/read", "staged plugin copies", "registry key path"],
            },
        },
    })


# --- interleave --------------------------------------------------------------------------------------------------------

def interleave() -> None:
    results = ["FX result op=%d value=%d" % (op, op * 3 + pool) for pool, base in ((1, 1000), (2, 2000)) for op in range(base, base + 8)]
    out = results + ["FX completed=16 dropped=1", "FX address_reused=1 tags=111,222"]
    write("interleave", {
        "fixture": "interleave", "spec": ["14.2", "14.3"], "sources": ["interleave.c", "interleave_mod.c", "trace_common.h"],
        "outputs": ["interleave.exe", "interleave_mod.dll"],
        "functions": {"submit": "fx_submit", "submit_dropped": "fx_submit_dropped", "handle": "fx_handle_request",
                      "store_result": "fx_store_result", "complete": "fx_complete", "object_create": "fx_object_create",
                      "object_destroy": "fx_object_destroy", "handle_cycle": "fx_handle_cycle", "module_cycle": "fx_module_cycle",
                      "spawn_child": "fx_spawn_child", "child_work": "fx_child_work", "module_export": "fx_mod_value"},
        "runs": [{"id": "default", "program": "interleave.exe", "args": [], "max_seconds": 30, "exit_code": 0,
                  "stdout_lines": out + ["<regex>FX handle_reused=[01]", "FX module_status=0 base_changed=1",
                                         "FX children=0,0 pids_differ=1", "FX done"],
                  "note": "lines starting with <regex> are matched as regular expressions (handle values may differ)"}],
        "answers": {
            "pools": {"P": {"pool_number": 1, "ops": list(range(1000, 1008)), "submit_pool_index": 0, "workers": 2},
                      "Q": {"pool_number": 2, "ops": list(range(2000, 2008)), "submit_pool_index": 1, "workers": 2}},
            "correlation_chain": {
                "per_op": ["fx_submit(pool_index, op)", "fx_handle_request(pool_number, op, worker)", "fx_store_result(op, value)", "fx_complete(op)"],
                "identity": "the op argument (1000..1007, 2000..2007)", "value": "op*3 + pool_number",
                "handoff": "fx_submit runs on the main thread, fx_handle_request on a pool thread (queue plus semaphore): a call stack does not connect them",
            },
            "interleaving": "main alternates P and Q submissions, so events of the two pools interleave; ops of P (1xxx) and Q (2xxx) are unrelated",
            "explanation_for_op_1003": {"must_include": ["fx_submit", "fx_handle_request", "fx_store_result", "fx_complete"], "must_not_include_ops": list(range(2000, 2008)) + [9999]},
            "missing_link": {"op": 9999, "events": ["fx_submit_dropped(1, 9999)"], "never_followed_by": ["fx_handle_request", "fx_store_result", "fx_complete"],
                             "expected_report": "request 9999 has no handler: unresolved boundary, not connected to the nearest-timestamp handler"},
            "identity_reuse": {
                "address": {"api": "VirtualAlloc/VirtualFree/VirtualAlloc at the same address", "tags": [111, 222], "reused": True,
                            "lifetimes": 2, "functions": ["fx_object_create", "fx_object_destroy"]},
                "handle": {"api": "CreateEventA, CloseHandle, CreateEventA", "reused_expected": "almost always (printed handle_reused)", "function": "fx_handle_cycle"},
                "module": {"dll": "interleave_mod.dll", "loads": 2, "second_base_differs": True,
                           "how": "the old image range is reserved after FreeLibrary, so the reload must move", "function": "fx_module_cycle"},
                "process": {"children": 2, "program": "interleave.exe --child", "pids_differ": True,
                            "note": "a PID cannot be forced to repeat; two sequential child generations are produced, PID reuse is covered by synthetic events"},
            },
            "no_silent_merge": "events with the same address, handle or module base but different lifetime/load instance stay distinct identities",
        },
    })


# --- layouts -----------------------------------------------------------------------------------------------------------

def layouts() -> None:
    stream = b""
    messages = []

    def add(kind: str, layout: int, raw: bytes, fields: dict) -> None:
        nonlocal stream
        messages.append({"index": len(messages), "kind": kind, "layout": layout, "offset": len(stream), "length": len(raw),
                         "hex": raw.hex(), "fields": fields})
        stream += raw

    for i in range(3):
        add("v1", 1, struct.pack("<HHII", 1, 12, 100 + i, 1000 + i * 7), {"id": 100 + i, "amount": 1000 + i * 7})
    add("negotiation", 1, struct.pack("<HHH", 0xF0, 6, 2), {"version": 2})
    for i in range(3):
        add("v2", 2, struct.pack("<HHQIH3s", 2, 21, 5000000000 + i, 2000 + i * 13, 0x8001 + i, bytes([0xE0, 0xE1, 0xE2])),
            {"id": 5000000000 + i, "amount": 2000 + i * 13, "flags": 0x8001 + i, "ext": "e0e1e2"})
    out = ["FX recv v1 id=%d amount=%d" % (100 + i, 1000 + i * 7) for i in range(3)] + ["FX recv negotiated version=2"]
    out += ["FX recv v2 id=%d amount=%d flags=0x%04x ext=e0e1e2" % (5000000000 + i, 2000 + i * 13, 0x8001 + i) for i in range(3)]
    out.append("FX stream_bytes=%d" % len(stream))
    write("layouts", {
        "fixture": "layouts", "spec": ["14.5"], "sources": ["layouts.c", "trace_common.h"], "outputs": ["layouts.exe"],
        "functions": {"encode_v1": "fx_encode_v1", "encode_v2": "fx_encode_v2", "encode_negotiation": "fx_encode_negotiation",
                      "negotiate": "fx_negotiate", "send": "fx_send", "receive": "fx_receive"},
        "runs": [{"id": "default", "program": "layouts.exe", "args": ["{work}/layouts.bin"], "max_seconds": 10, "exit_code": 0,
                  "stdout_lines": out, "files": {"layouts.bin": {"hex": stream.hex()}}}],
        "answers": {
            "layouts": {
                "1": {"type": 1, "length": 12, "fields": [["type", "u16", 0], ["length", "u16", 2], ["id", "u32", 4], ["amount", "u32", 8]]},
                "negotiation": {"type": 240, "length": 6, "fields": [["type", "u16", 0], ["length", "u16", 2], ["version", "u16", 4]]},
                "2": {"type": 2, "length": 21, "fields": [["type", "u16", 0], ["length", "u16", 2], ["id", "u64", 4], ["amount", "u32", 12],
                                                           ["flags", "u16", 16], ["ext", "u8[3]", 18]]},
            },
            "stream_bytes": len(stream), "stream_hex": stream.hex(), "messages": messages,
            "context_intervals": [{"layout": 1, "byte_range": [0, 36], "messages": [0, 1, 2]},
                                  {"event": "context change by negotiation message", "byte_range": [36, 42], "function": "fx_negotiate", "to_version": 2},
                                  {"layout": 2, "byte_range": [42, len(stream)], "messages": [4, 5, 6]}],
            "unconsumed": {"scenario": "a codec revision that decodes layout 2 only up to flags (18 bytes)",
                           "ranges": [[m["offset"] + 18, m["offset"] + 21] for m in messages if m["kind"] == "v2"], "bytes_each": 3},
            "corrected_codec": "reads ext as u8[3] and consumes all 21 bytes; reprocessing both layouts gives two interpretation revisions and keeps the original byte observations",
            "round_trip": "fx_encode_* of the decoded fields reproduces the bytes exactly",
        },
    })


# --- frameloop ---------------------------------------------------------------------------------------------------------

def simulate_frameloop(frames: int = 60, every: int = 10, overwrite: bool = True, ours_render: bool = False) -> dict:
    value, writer, write_frame = 0, 0, -1
    total = survived = overwritten = before = 0
    per_frame = []
    for frame in range(frames):
        if not ours_render:
            value, writer, write_frame = 5000 + frame, 1, frame
        if overwrite and frame % every != every - 1:
            value, writer, write_frame = 9000 + frame, 2, frame
        seen = value
        if write_frame == frame and writer == 1:
            survived += 1
            verdict = "survived"
        elif write_frame == frame and writer == 2:
            overwritten += 1
            verdict = "overwritten by fx_host_overwrite"
        else:
            before += 1
            verdict = "consumer read before write"
        per_frame.append(verdict)
        total += seen
        if ours_render:
            value, writer, write_frame = 5000 + frame, 1, frame
    return {"consumer_sum": total, "survived": survived, "overwritten": overwritten, "read_before_write": before, "per_frame": per_frame}


def frameloop() -> None:
    frames = 60
    callback_sum, physics_sum = sum(range(frames)), sum(2 * f for f in range(frames))

    def config(name: str, args: list[str], **model) -> dict:
        m = simulate_frameloop(frames, **model)
        out = ["FX frames=%d" % frames, "FX callback_sum=%d physics_sum=%d" % (callback_sum, physics_sum), "FX consumer_sum=%d" % m["consumer_sum"],
               "FX verdicts survived=%d overwritten=%d read_before_write=%d" % (m["survived"], m["overwritten"], m["read_before_write"])]
        return {"id": name, "program": "frameloop.exe", "args": args, "max_seconds": 20, "exit_code": 0, "stdout_lines": out}, m

    default, md = config("default", [])
    worker, _ = config("callback_on_worker", ["--callback-on=worker"])
    late, ml = config("ours_write_in_render", ["--ours-stage=render"], ours_render=True)
    keep, mk = config("no_overwrite", ["--no-overwrite"], overwrite=False)
    nomark, _ = config("skip_update_marker", ["--skip-marker=update"])
    late_keep, mlk = config("ours_in_render_no_overwrite", ["--ours-stage=render", "--no-overwrite"], ours_render=True, overwrite=False)
    survivors = [f for f, v in enumerate(md["per_frame"]) if v == "survived"]
    write("frameloop", {
        "fixture": "frameloop", "spec": ["15.2", "15.3", "14.8"], "sources": ["frameloop.c", "trace_common.h"], "outputs": ["frameloop.exe"],
        "functions": {"frame_begin": "fx_frame_begin", "frame_end": "fx_frame_end", "phase_begin": "fx_phase_begin",
                      "stage_input": "fx_stage_input", "stage_update": "fx_stage_update", "stage_render": "fx_stage_render",
                      "job_callback": "fx_job_callback", "job_physics": "fx_job_physics", "pool_thread": "fx_pool_thread",
                      "ours_write": "fx_ours_write", "host_overwrite": "fx_host_overwrite", "consume": "fx_consume"},
        "data": {"entity": "g_entity"},
        "entity_layout": ["tag:int@0", "value:int@4", "writer:int@8", "write_frame:int@12"],
        "runs": [default, worker, late, keep, nomark, late_keep],
        "answers": {
            "frames_default": frames,
            "phases": {"1": "input (fx_stage_input)", "2": "update (fx_stage_update)", "3": "render (fx_stage_render)", "marker": "fx_phase_begin(stage number)", "frame_markers": ["fx_frame_begin", "fx_frame_end"]},
            "roles": {"main": "the thread that runs main: frame markers, stages and (default) fx_job_callback",
                      "worker": "pool threads whose start function is fx_pool_thread: fx_job_physics every frame, fx_job_callback with --callback-on=worker"},
            "only_on_main_check": {"function": "fx_job_callback", "default_run": "passes (all 60 calls on main)",
                                   "callback_on_worker_run": "fails with a cited fx_job_callback event on a worker role", "calls_per_run": frames},
            "ordering_check": {"rule": "fx_ours_write precedes fx_consume in the same frame",
                               "default_run": "passes for 60 frames", "ours_write_in_render_run": "fails: fx_consume runs before fx_ours_write in every frame (60)"},
            "missing_marker": {"run": "skip_update_marker", "expect": "phase 'update' has no marker: role/phase keys unresolved and checks over it are unknown, not pass",
                               "missing_phase": 2},
            "intervention_outcome": {
                "field": "g_entity.value (offset 4)", "consumer": "fx_consume", "our_write": "fx_ours_write", "overwriting_site": "fx_host_overwrite",
                "default": {"frames": frames, "survived_frames": survivors, "overwritten": md["overwritten"], "survived": md["survived"],
                            "ratio": "%d of %d frames overwritten by fx_host_overwrite" % (md["overwritten"], frames),
                            "values": {"ours": "5000+frame", "host": "9000+frame"}},
                "no_overwrite": {"verdicts": "every frame survived", "survived": mk["survived"]},
                "ours_write_in_render": {"verdicts": "consumer read before write on %d frames, overwritten on %d" % (ml["read_before_write"], ml["overwritten"]),
                                         "read_before_write": ml["read_before_write"], "overwritten": ml["overwritten"]},
                "ours_in_render_no_overwrite": {"read_before_write": mlk["read_before_write"]},
                "per_frame_default": md["per_frame"],
            },
            "no_frame_without_event": {"event": "fx_host_overwrite", "default_run_frames_without": survivors},
            "at_most_once_per_frame": ["fx_ours_write", "fx_host_overwrite", "fx_consume"],
            "performance_use": "frameloop.exe --frames=200000 is the overhead benchmark (about 1 s unhooked)",
        },
    })


# --- veh_freeze --------------------------------------------------------------------------------------------------------

def veh_freeze() -> None:
    write("veh_freeze", {
        "fixture": "veh_freeze", "spec": ["15.1"], "sources": ["veh_freeze.c", "trace_common.h"], "outputs": ["veh_freeze.exe"],
        "functions": {"handler": "fx_freezing_handler", "read_object": "fx_read_object"},
        "data": {"heartbeat": "g_heartbeat", "handler_ran": "g_handler_ran", "suspended_threads": "g_suspended_threads"},
        "runs": [
            {"id": "wait", "program": "veh_freeze.exe", "args": ["--seconds=1"], "max_seconds": 20, "exit_code": 0,
             "stdout_lines": ["<regex>FX debugger=[01]", "<regex>FX freed_object=0x[0-9A-Fa-f]{8,16}", "FX ready", "FX handler_ran=0 heartbeat_advanced=1", "FX done"]},
            {"id": "selftest", "program": "veh_freeze.exe", "args": ["--mode=selftest"], "max_seconds": 20, "exit_code": 0,
             "stdout_lines": ["<regex>FX debugger=[01]", "<regex>FX freed_object=0x[0-9A-Fa-f]{8,16}", "FX ready",
                              "FX faulted=1 handler_ran=1 heartbeat_frozen=1", "FX done"]},
        ],
        "answers": {
            "handler": {"registration": "AddVectoredExceptionHandler(first=1, fx_freezing_handler) in main",
                        "actions": ["thread suspension of every other thread on the first first-chance EXCEPTION_ACCESS_VIOLATION"],
                        "fault_policy": "freezes"},
            "freed_object": "VirtualAlloc'd page, decommitted (reserved): any read faults; its address is printed as freed_object",
            "non_faulting_probe": {"expected_result": "read failure counted and cited, no exception raised", "g_handler_ran": 0,
                                   "process": "keeps running; the heartbeat advances; exit code 0", "fault_free_claim": True},
            "faulting_probe": {"expected_result": "handler runs (g_handler_ran >= 1) and suspends other threads: this is the fixture's selftest mode, not a thing a probe may do",
                               "selftest_lines": ["faulted=1 handler_ran=1 heartbeat_frozen=1"]},
            "debugger_note": "the debugger line records IsDebuggerPresent; under a debugger the session context must record the difference",
            "refusal": "a probe that cannot be made non-faulting under fault policy 'freezes' is refused, not armed",
        },
    })


# --- vcall_fixture -----------------------------------------------------------------------------------------------------

def vcall_fixture() -> None:
    out = []
    for frame in range(3):
        out += ["FX frame=%d direct=%d" % (frame, (frame + 1) * 2), "FX frame=%d slot=%d" % (frame, (frame + 1) * 3)]
    write("vcall_fixture", {
        "fixture": "vcall_fixture", "spec": ["15.4", "static vcalls (existing)"], "sources": ["vcall_fixture.cpp"], "outputs": ["vcall_fixture.exe"],
        "functions": {"direct_wrapper": "fx_put_direct", "slot_wrapper": "fx_put_slot", "get": "fx_store_get",
                      "direct_overload": "Counter::put!direct", "slot_overload": "Counter::put", "get_impl": "Store::get"},
        "data": {"counter_vftable": "Counter::vftable", "counter": "g_counter"},
        "runs": [{"id": "three_frames", "program": "vcall_fixture.exe", "args": ["{work}/no-stop-file", "3"], "max_seconds": 20, "exit_code": 0,
                  "stdout_lines": out}],
        "answers": {
            "field": {"class": "Store", "name": "value", "type": "int", "offset": {"x64": 8, "x86": 4}, "note": "after the vftable pointer"},
            "writers": {
                "Counter::put(int)": {"symbol_key": "Counter::put!direct", "reached_by": "fx_put_direct, a direct (non-virtual) call", "writes": "value = v * 2"},
                "Counter::put(long long)": {"symbol_key": "Counter::put", "virtual": True, "slot": {"x64": "0x8", "x86": "0x4"}, "slot_index": 1,
                                            "reached_by": "fx_put_slot through Store::put (vtable slot 1) on a Counter receiver", "writes": "value = (int)v * 3"},
            },
            "hook_bypass": {"hooked": "Counter::put!direct", "bypassed_by": "Counter::put",
                            "observed_path": ["main", "fx_put_slot", "[indirect call, slot 1]", "Counter::put"], "receiver_class": "Counter",
                            "kind": "sibling overload reached through a vtable slot"},
            "values_per_frame": [{"frame": f, "direct": (f + 1) * 2, "slot": (f + 1) * 3} for f in range(3)],
            "static_vs_observed": "static vcalls lists fx_put_slot (slot 1) as a candidate; only the runtime shows Counter::put ran; an unobserved slot stays 'may call'",
        },
    })


# --- replica -----------------------------------------------------------------------------------------------------------

def replica() -> None:
    steps, outage_from, outage_to, owner_only_from = 200, 60, 160, 30
    sent = [s for s in range(steps) if not outage_from <= s < outage_to]
    write("replica", {
        "fixture": "replica", "spec": ["15.5", "14.3"], "sources": ["replica_a.c", "replica_b.c", "replica_common.h", "trace_common.h"],
        "outputs": ["replica_a.exe", "replica_b.exe"],
        "functions": {"truth": "fx_truth_publish", "truth_create": "fx_truth_create", "send": "fx_send_message", "send_sync": "fx_send_sync",
                      "mirror": "fx_mirror_apply", "extrapolate": "fx_mirror_extrapolate", "receive_sync": "fx_receive_sync"},
        "runs": [{
            "id": "pair", "program": "replica_b.exe", "args": ["{tag}", "{work}/replica.jsonl", "250"], "max_seconds": 30, "exit_code": 0,
            "stdout_lines": ["FX replica applied=100 extrapolated=1"],
            "companion": {"program": "replica_a.exe", "args": ["{tag}", "{work}/owner.jsonl"], "exit_code": 0,
                          "stdout_lines": ["FX owner listening", "FX owner sent=100 skipped=100 objects=2"]},
        }],
        "answers": {
            "roles": {"owner": "replica_a.exe", "replica": "replica_b.exe", "correlation_key": "obj (logical object id)", "transport": "named pipe \\\\.\\pipe\\hydra_replica_<tag>"},
            "events": {"truth": "fx_truth_publish(obj, seq, value) on the owner", "mirror": "fx_mirror_apply(obj, seq, value) on the replica",
                       "extrapolated": "fx_mirror_extrapolate(obj, last_seq, value) on the replica", "schema": "obj, seq, value (same fields on both sides)"},
            "objects": {"1": {"present_on": ["owner", "replica"], "value_of_seq": "seq * 7", "ticks": steps, "tick_ms": 20},
                        "2": {"present_on": ["owner"], "created_at_seq": owner_only_from, "expected_report": "object created only on the owner"}},
            "delay_ms": 100, "delay_tolerance_ms": [100, 160], "delay_note": "applied delay is 100 ms plus up to a tick and poll of jitter (the replica polls the pipe and ticks every 20 ms)",
            "outage": {"owner_ticks": [outage_from, outage_to], "duration_ms": 2000, "messages_not_sent": outage_to - outage_from,
                       "expected_mirror_seqs_missing": [outage_from, outage_to],
                       "expected_report": "interval unknown (replica stopped reporting), not agreement; extrapolated replica ticks cover it"},
            "mirror_seqs_expected": sent, "mirror_count": len(sent), "extrapolated_ticks_min": 80,
            "clock": {"replica_offset_ms": 250, "calibration": "replica sync receive time minus owner send time = offset + latency",
                      "offset_range_ms": [250, 290], "markers": 3, "marker_kind": "sync", "units": "ms", "domain": "QueryPerformanceCounter, one machine"},
            "log_format": "JSON lines with side, kind, t_ms, obj, seq, value",
        },
    })


# --- fnv_names ---------------------------------------------------------------------------------------------------------

def fnv_names() -> None:
    rows = gen_fnv_names.records()
    out = ["FX record name=%s hash=0x%016x id=%d" % (n, h, i) for n, h, i in rows]
    a, b = gen_fnv_names.COLLISION
    h = gen_fnv_names.fnv1a64(a)
    out.append("FX collision a=%s b=%s hash_a=0x%016x hash_b=0x%016x same=1 id=%d" % (a, b, h, h, gen_fnv_names.COLLISION_ID))
    out.append("FX known=64")
    write("fnv_names", {
        "fixture": "fnv_names", "spec": ["15.6"], "sources": ["fnv_names.c", "gen_fnv_names.py", "find_fnv_collision.c", "trace_common.h"],
        "outputs": ["fnv_names.exe"],
        "functions": {"hash": "fx_fnv1a64", "dispatch": "fx_dispatch_record"},
        "data": {"names": "g_names"},
        "runs": [{"id": "default", "program": "fnv_names.exe", "args": [], "max_seconds": 10, "exit_code": 0, "stdout_lines": out}],
        "answers": {
            "algorithm": {"name": "FNV-1a 64", "offset_basis": "0xcbf29ce484222325", "prime": "0x100000001b3", "test_vector": {"": "0xcbf29ce484222325", "a": "0xaf63dc4c8601ec8c", "foobar": "0x85944171f73967e8"}},
            "records": [{"name": n, "hash": "0x%016x" % hh, "id": i} for n, hh, i in rows],
            "constants_live_in": "fx_dispatch_record (64-bit immediates of the switch; on x86 each splits into two 32-bit immediates)",
            "name_search": {"query": "player.health", "hash": "0x%016x" % rows[0][1], "finds_function": "fx_dispatch_record"},
            "annotation": "each immediate equal to a record hash is annotated with its name and the dictionary source (the name strings in g_names)",
            "collision": {"names": [a, b], "hash": "0x%016x" % h, "id": gen_fnv_names.COLLISION_ID,
                          "expected_report": "ambiguous: two names, one hash; never silently resolved",
                          "found_with": "find_fnv_collision.c (rho search)"},
        },
    })


# --- minivm ------------------------------------------------------------------------------------------------------------

def minivm() -> None:
    natives = [("add", "fx_nat_add", 2, "table"), ("sub", "fx_nat_sub", 2, "table"), ("mul", "fx_nat_mul", 2, "table"),
               ("neg", "fx_nat_neg", 1, "table"), ("min", "fx_nat_min", 2, "table"), ("max", "fx_nat_max", 2, "table"),
               ("clamp", "fx_nat_clamp", 3, "table"), ("abs", "fx_nat_abs", 1, "table"), ("sq", "fx_nat_sq", 1, "table"),
               ("avg3", "fx_nat_avg3", 3, "table"), ("dist2", "fx_nat_dist2", 4, "call"), ("select", "fx_nat_select", 3, "call")]
    script = [("add", [2, 3], 5), ("sub", [10, 4], 6), ("mul", [6, 7], 42), ("neg", [5], -5), ("min", [9, 3], 3), ("max", [9, 3], 9),
              ("clamp", [15, 0, 10], 10), ("abs", [-8], 8), ("sq", [12], 144), ("avg3", [3, 6, 9], 6), ("dist2", [0, 0, 3, 4], 25),
              ("select", [1, 111, 222], 111)]
    nargs = {n: k for n, _s, k, _r in natives}
    out = ["FX registered=12"] + ["FX call name=%s args=%d result=%d" % (n, nargs[n], r) for n, _a, r in script] + ["FX script_ok=12"]
    write("minivm", {
        "fixture": "minivm", "spec": ["15.7"], "sources": ["minivm.c", "trace_common.h"], "outputs": ["minivm.exe"],
        "functions": {"register": "fx_vm_register", "load_table": "fx_vm_load_table", "find": "fx_vm_find", "dispatch": "fx_vm_dispatch",
                      "run_line": "fx_vm_run_line"},
        "data": {"table": "g_native_table"},
        "runs": [{"id": "default", "program": "minivm.exe", "args": [], "max_seconds": 10, "exit_code": 0, "stdout_lines": out}],
        "answers": {
            "registration": {"table": {"symbol": "g_native_table", "row": "{const char *name; native_fn fn; int nargs}", "rows": 10, "loader": "fx_vm_load_table"},
                             "calls": {"function": "fx_vm_register", "sites": 2, "names": ["dist2", "select"]}},
            "natives": [{"script_name": n, "native": s, "params": k, "registered_by": r} for n, s, k, r in natives],
            "total_natives": 12, "table_natives": 10, "call_natives": 2,
            "signature": "int native(const int *args); params = declared nargs",
            "script": [{"line": "%s %s" % (n, " ".join(map(str, a))), "native": n, "args": a, "result": r} for n, a, r in script],
            "cross_layer_edge": "script call line -> fx_vm_dispatch (indirect call through Native.fn) -> fx_nat_<name>",
            "trace_link": "a fx_vm_run_line event for 'sq 12' links to the fx_nat_sq event with args [12] and result 144",
        },
    })


# --- persist -----------------------------------------------------------------------------------------------------------

def store(records: list[tuple[int, int, int, str]]) -> bytes:
    body = b"HPSV" + struct.pack("<II", 1, len(records))
    for rid, rtype, value, tag in records:
        body += struct.pack("<IIi8s", rid, rtype, value, tag.encode())
    return body


def persist() -> None:
    defaults = [(1, 1, 100, "hp"), (2, 1, 1, "flags"), (3, 1, 250, "gold"), (4, 2, 0, "boss01")]
    poked = [(1, 1, 100, "hp"), (2, 1, 0, "flags"), (3, 1, 250, "gold"), (4, 2, 0, "boss01")]

    def saved(records, tag="saved"):
        return ["FX %s id=%d type=%d value=%d tag=%s" % (tag, i, t, v, g) for i, t, v, g in records]

    write("persist", {
        "fixture": "persist", "spec": ["15.8"], "sources": ["persist.c", "trace_common.h"], "outputs": ["persist.exe"],
        "functions": {"write_store": "fx_write_store", "read_store": "fx_read_store", "poke": "fx_instrument_poke", "defaults": "fx_defaults"},
        "sequence": [
            {"id": "save_baseline", "program": "persist.exe", "args": ["{work}", "save"], "max_seconds": 10, "exit_code": 0,
             "stdout_lines": saved(defaults) + ["FX saved_count=4 poke=0"],
             "files": {"persist_before.dat": {"hex": store(defaults).hex()}, "persist_save.dat": {"hex": store(defaults).hex()}}},
            {"id": "save_with_intervention", "program": "persist.exe", "args": ["{work}", "save", "--poke"], "max_seconds": 10, "exit_code": 0,
             "stdout_lines": saved(poked) + ["FX saved_count=4 poke=1"],
             "files": {"persist_before.dat": {"hex": store(defaults).hex()}, "persist_save.dat": {"hex": store(poked).hex()}}},
            {"id": "fresh_load", "program": "persist.exe", "args": ["{work}", "load"], "max_seconds": 10, "exit_code": 0,
             "stdout_lines": ["FX dropped id=4 type=2"] + saved(poked[:3], "loaded") + ["FX loaded_count=3 dropped=1"],
             "files": {"persist_save.dat": {"hex": store(poked).hex()}}},
        ],
        "answers": {
            "store": "persist_save.dat in the work dir; before-image persist_before.dat",
            "record_layout": "20 bytes: u32 id, u32 type, i32 value, char tag[8]; header 'HPSV', u32 version=1, u32 count",
            "intervention": {"function": "fx_instrument_poke(2, 0)", "record": {"id": 2, "name": "flags", "before": 1, "after": 0, "byte_offset_of_value": 12 + 20 + 8},
                             "classification": "intervention-caused, survives removing the intervention (it is in the file)",
                             "attribution": "the write is observed at fx_instrument_poke; unattributed if no write was observed"},
            "ordinary_changes": "none: the other records and the header are byte-identical between persist_before.dat and persist_save.dat",
            "round_trip": {"present_after_reload": [1, 2, 3], "did_not_round_trip": [{"id": 4, "type": 2, "tag": "boss01", "report": "did not round-trip"}]},
            "removal_check": "after the intervention is removed a plain load still sees flags=0",
        },
    })


# --- deadlock ----------------------------------------------------------------------------------------------------------

def deadlock() -> None:
    write("deadlock", {
        "fixture": "deadlock", "spec": ["15.9"], "sources": ["deadlock.c", "trace_common.h"], "outputs": ["deadlock.exe"],
        "functions": {"main_frame": "fx_main_frame", "main_lock_sequence": "fx_main_lock_a_then_b", "handler": "fx_suspend_all_handler"},
        "data": {"frame_counter": "g_frame"},
        "runs": [
            {"id": "deadlock", "program": "deadlock.exe",
             "args": ["--mode=deadlock", "--hold=1", "--state-file={work}/state.txt", "--dump={work}/deadlock.dmp"], "max_seconds": 30, "exit_code": 0,
             "stdout_lines": ["FX frames=20", "FX state=deadlocked", "FX frames_before_freeze=1", "FX dump_written=1", "FX reaper exit"],
             "files": {"state.txt": {"text": "deadlocked frame=20\n"}, "deadlock.dmp": {"prefix_hex": "4d444d50"}}},
            {"id": "suspend_all", "program": "deadlock.exe",
             "args": ["--mode=suspend-all", "--hold=1", "--state-file={work}/state.txt", "--dump={work}/suspend.dmp"], "max_seconds": 30, "exit_code": 0,
             "stdout_lines": ["FX frames=20", "FX state=suspended_all", "FX frames_before_freeze=1", "FX dump_written=1", "FX reaper exit"],
             "files": {"suspend.dmp": {"prefix_hex": "4d444d50"}}, "state_file_regex": {"state.txt": "^suspended_all frame=(2[0-9]|[3-9][0-9])$"}},
        ],
        "answers": {
            "main_loop": {"counter": "g_frame", "function": "fx_main_frame", "period_ms": 20, "frames_before_freeze": {"deadlock": 20, "suspend-all": ">=20"},
                          "watchdog": "g_frame stops advancing when the bad state is reached"},
            "deadlock": {"threads": {"main": "holds lock A (g_lock_a), waits for lock B inside fx_main_lock_a_then_b",
                                     "worker": "fx_worker_b_then_a: holds lock B (g_lock_b), waits for lock A"},
                         "locks": "two CRITICAL_SECTIONs; each waiter's blocker is the other thread (owner resolvable from OwningThread)",
                         "pattern": "N=2 threads waiting on locks held by each other", "state_file": "deadlocked frame=20", "hold_seconds": 1},
            "suspend_all": {"handler": "fx_suspend_all_handler (vectored, first in chain)", "suspended_by": "the faulting worker thread (fx_faulting_worker)",
                            "worker_state": "waits inside the fault handler (thread inside the host's fault handler)",
                            "survivors": ["reaper thread", "fixture watchdog thread"], "pattern": "all threads suspended by thread T (T = the worker in the handler)",
                            "fault": "read of a decommitted page at g_freed"},
            "dump": "--dump writes a minidump of the process itself (MDMP magic) from the reaper thread while the bad state holds",
            "exit": "the reaper ends the process with exit code 0 after --hold seconds; the safety watchdog exits 99 after hold+40 s",
        },
    })


# --- diff_fixture ------------------------------------------------------------------------------------------------------

def diff_fixture() -> None:
    write("diff_fixture", {
        "fixture": "diff_fixture", "spec": ["15.10", "diff (existing)"], "sources": ["diff_fixture.c"], "outputs": ["diff1.exe", "diff2.exe"],
        "functions": {"codec": "df_decode_amount", "moved_hook": "df_render", "moved_hook_2": "df_mix", "removed": "df_removed", "added": "df_added",
                      "changed_limit": "df_limit", "changed_banner": "df_banner"},
        "runs": [
            {"id": "build_A", "program": "diff1.exe", "args": [], "max_seconds": 10, "exit_code": 0,
             "stdout_lines": ["<regex>^-?[0-9]+$", "FX amount=907 offset=8 size=12"]},
            {"id": "build_B", "program": "diff2.exe", "args": [], "max_seconds": 10, "exit_code": 0,
             "stdout_lines": ["<regex>^-?[0-9]+$", "FX amount=907 offset=12 size=16"]},
        ],
        "answers": {
            "builds": {"A": "diff1.exe", "B": "diff2.exe (-DV2)"},
            "corpus_diff": {"type": "Record", "A": [["id", "int", 0], ["version", "int", 4], ["amount", "int", 8]],
                            "B": [["id", "int", 0], ["version", "int", 4], ["inserted", "int", 8], ["amount", "int", 12]],
                            "changes": [{"field": "inserted", "status": "added"}, {"field": "amount", "status": "moved", "from": 8, "to": 12}],
                            "sizeof": {"A": 12, "B": 16}},
            "invalidation": {
                "moved": ["codec layout decoding Record.amount (offset 8 -> 12), implemented by df_decode_amount"],
                "candidate": ["hook-table row on df_render (identical code, placed elsewhere in B)"],
                "unplaced": ["evidence on df_removed (exists in A only)"],
                "carried": ["df_parse", "df_checksum", "df_format", "df_scale", "df_lookup", "df_walk", "(identical bytes)"],
                "changed_functions": ["df_limit", "df_banner", "df_decode_amount"], "new_in_B": ["df_added"],
                "promotion": "nothing is promoted to B automatically",
            },
            "decoded_amount": 907, "note": "df_decode_amount returns amount (900) + df_parse(\"7\"); the same value in both builds only because the codec follows the layout",
        },
    })


# --- ioctl_client ------------------------------------------------------------------------------------------------------

def ioctl_client() -> None:
    write("ioctl_client", {
        "fixture": "ioctl_client", "spec": ["decision 6", "user-mode driver-boundary events"], "sources": ["ioctl_client.c", "trace_common.h"],
        "outputs": ["ioctl_client.exe"],
        "functions": {"open": "fx_open_device", "nul_write": "fx_nul_write", "nul_read": "fx_nul_read", "nul_ioctl": "fx_nul_ioctl",
                      "beep_stop": "fx_beep_stop", "beep_bad": "fx_beep_bad"},
        "runs": [{"id": "default", "program": "ioctl_client.exe", "args": [], "max_seconds": 20, "exit_code": 0,
                  "stdout_lines": ["FX nul_open ok=1", "FX nul_write ok=1 written=16", "<regex>FX nul_read ok=[01] got=0",
                                   "FX nul_ioctl code=0x00152000 ok=0 error=1 returned=0", "<regex>FX beep_open ok=[01]",
                                   "<optional>FX beep_stop code=0x00010000 ok=[01] error=[0-9]+",
                                   "<optional>FX beep_bad code=0x00010000 ok=[01] error=[0-9]+", "FX done"]}],
        "answers": {
            "devices": [{"path": "\\\\.\\NUL", "always_present": True}, {"path": "\\\\.\\Beep", "always_present": False, "note": "the open may fail; the result is printed, never asserted"}],
            "calls": [
                {"api": "CreateFileW", "path": "\\\\.\\NUL", "function": "fx_open_device"},
                {"api": "WriteFile", "handle": "NUL", "bytes": 16, "payload_ascii": "HYDRA-IOCTL-NUL!", "result": "16 written", "function": "fx_nul_write"},
                {"api": "ReadFile", "handle": "NUL", "bytes_requested": 16, "result": "0 bytes", "function": "fx_nul_read"},
                {"api": "DeviceIoControl", "handle": "NUL", "code": "0x00152000", "device_type": "0x15", "function_number": "0x800", "method": "buffered",
                 "in_bytes": 8, "in_payload_ascii": "HYDRAIOC", "out_bytes": 8, "result": "failure, ERROR_INVALID_FUNCTION (1)", "function": "fx_nul_ioctl"},
                {"api": "CreateFileW", "path": "\\\\.\\Beep", "function": "fx_open_device", "environment_dependent": True},
                {"api": "DeviceIoControl", "handle": "Beep", "code": "0x00010000", "in_bytes": 8, "in_payload_hex": "0000000000000000",
                 "meaning": "IOCTL_BEEP_SET with frequency 0 duration 0: silence", "function": "fx_beep_stop", "environment_dependent": True},
                {"api": "DeviceIoControl", "handle": "Beep", "code": "0x00010000", "in_bytes": 4, "meaning": "short input, rejected", "function": "fx_beep_bad",
                 "environment_dependent": True},
            ],
            "no_driver_of_ours": True,
            "boundary_events": "user-mode only: CreateFile, DeviceIoControl, WriteFile, ReadFile and CloseHandle with code, buffer sizes and status",
        },
    })


def main() -> None:
    for build in (trace_app, interleave, layouts, frameloop, veh_freeze, vcall_fixture, replica, fnv_names, minivm, persist,
                  deadlock, diff_fixture, ioctl_client):
        build()


if __name__ == "__main__":
    main()
