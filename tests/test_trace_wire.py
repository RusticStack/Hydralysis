"""The trace wire layer: the pure-Python twin is correct on its own, and the Rust encoder gives identical bytes."""

from __future__ import annotations

import hashlib
import json
import hmac
import random
import unittest

from hydralysis import trace_wire as tw

try:
    import hydralysis_native as native  # type: ignore[import-not-found]
    HAVE_NATIVE = hasattr(native, "SegmentEncoder")
except ImportError:
    native, HAVE_NATIVE = None, False

KEY = bytes(range(32))
FREQ = 10_000_000
SITES = {
    1: {"name": "CreateFileW", "kind": "open", "module": "KernelBase.dll", "va": 0x7FF800001000},
    2: {"name": "DeviceIoControl", "kind": "ioctl", "module": "KernelBase.dll", "va": 0x7FF800002000, "buf": "payload"},
    3: {"name": "CM_Locate_DevNodeW", "kind": "devquery", "module": "cfgmgr32.dll", "va": 0x7FF800003000},
    4: {"name": "frame_tick", "kind": "call", "module": "game.exe", "va": 0x140001000, "buf": "id"},
    5: {"name": "SetupDiGetClassDevsW", "kind": "devquery", "module": "setupapi.dll", "va": 0x7FF800004000},
}


def wide(text: str) -> bytes:
    return text.encode("utf-16le") + b"\0\0"


def encoders(**options):
    args = ("seg-1", "agent", 3, 4242, SITES, KEY, FREQ)
    out = [tw.SegmentEncoder(*args, **options)]
    if HAVE_NATIVE:
        out.append(native.SegmentEncoder(*args, **options))
    return out


def open_rec(ring, seq, qpc, path, handle, **extra):
    return {"site": 1, "ring": ring, "ring_seq": seq, "qpc": qpc, "tid": 100 + ring, "ret_addr": 0x7FF800009999,
            "qpc_end": qpc + 50, "retval": handle, "flags": tw.F_RET | tw.F_WIDE, "args": [0, 0x80000000, 3, 0, 3, 0],
            "buf": wide(path), "buf_addr": 0x1000, "last_error": 0, **extra}


def ioctl_rec(ring, seq, qpc, handle, code, **extra):
    return {"site": 2, "ring": ring, "ring_seq": seq, "qpc": qpc, "tid": 100 + ring, "ret_addr": 0x7FF8000099AA,
            "qpc_end": qpc + 20, "retval": 1, "flags": tw.F_RET, "args": [handle, code, 0, 4, 0, 8, 0, 0],
            "buf": b"\x01\x02\x03\x04", "buf_addr": 0x2000, **extra}


class Canonical(unittest.TestCase):
    def test_sorted_ascii_minimal_and_del_escaped(self):
        value = {"b": 1, "a": ["x", "é", "😀", "\x7f", "\n"], "c": None, "d": True}
        self.assertEqual(tw.canon(value), b'{"a":["x","\\u00e9","\\ud83d\\ude00","\\u007f","\\n"],"b":1,"c":null,"d":true}')

    def test_floats_are_refused(self):
        with self.assertRaises(tw.WireError):
            tw.canon({"t": 1.5})

    def test_chain_matches_a_hand_computed_hash(self):
        chain = tw.Chain("s")
        line = chain.push({"k": 1})
        record = {"k": 1, "n": 0, "prev": tw.genesis_hash("s")}
        record["hash"] = hashlib.sha256(tw.canon(record)).hexdigest()
        self.assertEqual(line, tw.frame(record))
        self.assertEqual(chain.head, record["hash"])

    def test_keyed_id_is_a_truncated_hmac(self):
        self.assertEqual(tw.keyed_id(KEY, b"abc"), hmac.new(KEY, b"abc", hashlib.sha256).hexdigest()[:32])
        self.assertNotEqual(tw.keyed_id(KEY, b"abc"), tw.keyed_id(bytes(32), b"abc"))

    def test_device_path_detection(self):
        self.assertTrue(tw.is_device_path(wide("\\\\.\\NUL")))
        self.assertTrue(tw.is_device_path(wide("\\\\?\\GLOBALROOT\\Device\\Beep")))
        self.assertFalse(tw.is_device_path(wide("\\\\?\\C:\\Users\\x")))
        self.assertFalse(tw.is_device_path(wide("C:\\x")))

    def test_path_normalisation_is_ascii_only(self):
        self.assertEqual(tw.normalize_path(wide("C:/Users/É")), wide("c:\\users\\É"))


class Batches(unittest.TestCase):
    def test_batch_round_trips(self):
        records = [open_rec(0, 0, 10, "\\\\.\\NUL", 0x88), ioctl_rec(0, 1, 20, 0x88, 0x00220004)]
        header, back = tw.decode_batch(tw.build_batch(3, 0, 99, (2, 0, 0, 0), records))
        self.assertEqual((header["batch_seq"], header["count"], header["attempted"]), (0, 2, 2))
        self.assertEqual(back[0]["buf"], wide("\\\\.\\NUL"))
        self.assertEqual(back[1]["args"][1], 0x00220004)

    def test_damaged_batches_are_refused(self):
        good = tw.build_batch(3, 0, 1, (1, 0, 0, 0), [open_rec(0, 0, 10, "a", 1)])
        for bad in (good[:-1], good + b"\0", b"x" * 64, b"", bytes([good[0] ^ 1]) + good[1:]):
            with self.assertRaises(tw.WireError):
                tw.decode_batch(bad)
            if HAVE_NATIVE:
                with self.assertRaises(ValueError):
                    native.decode_batch(bad)

    @unittest.skipUnless(HAVE_NATIVE, "hydralysis_native with the trace encoder is not installed")
    def test_native_decoder_matches(self):
        batch = tw.build_batch(3, 5, 77, (9, 1, 0, 0), [open_rec(2, 7, 10, "C:\\a", 0x44), ioctl_rec(1, 0, 11, 1, 5)])
        self.assertEqual(tuple(native.decode_batch(batch)[0].items()), tuple(tw.decode_batch(batch)[0].items()))
        self.assertEqual(list(native.decode_batch(batch)[1]), tw.decode_batch(batch)[1])


class Encoding(unittest.TestCase):
    def run_both(self, script):
        """Run `script(encoder)` against every encoder and require identical bytes, artifacts and counters."""
        results = []
        for encoder in encoders(payload_authorized=True):
            results.append((script(encoder), encoder.head, encoder.count, dict(encoder.stats), encoder.source_seq))
        for other in results[1:]:
            self.assertEqual(other, results[0])
        return results[0][0]

    def test_a_device_open_and_an_ioctl_on_it(self):
        def script(e):
            b = tw.build_batch(3, 0, 1000, (2, 0, 0, 0), [open_rec(0, 0, 100, "\\\\.\\Beep", 0x88),
                                                          ioctl_rec(0, 1, 200, 0x88, 0x00010004)])
            lines, artifacts, info = e.encode_batch(b)
            return bytes(lines), {k: bytes(v) for k, v in artifacts.items()}, info
        lines, artifacts, info = self.run_both(script)
        text = lines.decode()
        for kind in ("core.resource.open", "driver.device_open", "core.resource.write", "driver.ioctl"):
            self.assertIn('"kind":"%s"' % kind, text)
        self.assertIn('"code":65540', text)
        self.assertIn('"resource_kind":"device"', text)
        self.assertNotIn("Beep", text)                       # a path never reaches the segment, only its keyed id
        self.assertEqual(len(artifacts), 1)                  # payload mode, authorized: the exact range
        self.assertEqual(next(iter(artifacts.values())), b"\x01\x02\x03\x04")
        self.assertEqual(info["records"], 2)
        # the open's id is the keyed id of the normalised path, and the ioctl joins on it
        rid = tw.keyed_id(KEY, wide("\\\\.\\beep")[:-2])
        self.assertEqual(text.count(rid), 4)

    def test_payload_is_refused_without_authorization(self):
        for encoder in encoders():
            lines, artifacts, _ = encoder.encode_batch(tw.build_batch(3, 0, 1, (1, 0, 0, 0), [ioctl_rec(0, 0, 5, 1, 4)]))
            self.assertEqual(dict(artifacts), {})
            self.assertIn(b"payload-not-authorized", bytes(lines))
            self.assertEqual(encoder.stats["payload_refused"], 1)

    def test_ioctl_on_an_unseen_handle_is_unresolved_not_guessed(self):
        for encoder in encoders():
            lines, _, _ = encoder.encode_batch(tw.build_batch(3, 0, 1, (1, 0, 0, 0), [ioctl_rec(0, 0, 5, 0x1234, 4)]))
            self.assertIn(b"lifetime-unresolved", bytes(lines))
            self.assertIn(b'"resource_id":null', bytes(lines))

    def test_ring_overflow_is_a_gap_with_its_range(self):
        def script(e):
            first = tw.build_batch(3, 0, 10, (1, 0, 0, 0), [open_rec(0, 0, 10, "a", 5)])
            second = tw.build_batch(3, 1, 20, (8, 6, 0, 0), [open_rec(0, 7, 90, "b", 6)])   # six attempts never arrived
            return bytes(e.encode_batch(first)[0]) + bytes(e.encode_batch(second)[0])
        text = self.run_both(script).decode()
        self.assertIn('"reason":"ring-overflow"', text)
        self.assertIn('"dropped":6', text)
        self.assertIn('"first_missing_source_seq":1', text)
        self.assertNotIn("producer-lost", text)

    def test_loss_the_counters_do_not_explain_is_a_lost_producer(self):
        def script(e):
            e.encode_batch(tw.build_batch(3, 0, 10, (1, 0, 0, 0), [open_rec(0, 0, 10, "a", 5)]))
            return bytes(e.encode_batch(tw.build_batch(3, 1, 20, (5, 0, 0, 0), [open_rec(0, 4, 90, "b", 6)]))[0])
        self.assertIn('"reason":"producer-lost"', self.run_both(script).decode())

    def test_a_missing_batch_is_a_transport_gap(self):
        def script(e):
            e.encode_batch(tw.build_batch(3, 0, 10, (1, 0, 0, 0), [open_rec(0, 0, 10, "a", 5)]))
            return bytes(e.encode_batch(tw.build_batch(3, 3, 20, (2, 0, 0, 0), [open_rec(0, 1, 30, "b", 6)]))[0])
        text = self.run_both(script).decode()
        self.assertIn('"hop":"transport"', text)
        self.assertIn('"batches_missing":2', text)

    def test_tail_loss_only_the_counters_know_is_reported_out_of_band(self):
        def script(e):
            e.encode_batch(tw.build_batch(3, 0, 10, (1, 0, 0, 0), [open_rec(0, 0, 10, "a", 5)]))
            return bytes(e.finalize([{"ring": 0, "attempted": 11, "dropped": 10}, {"ring": 1, "attempted": 0, "dropped": 0}], 500, no_ring=3))
        text = self.run_both(script).decode()
        self.assertEqual(text.count('"out_of_band":true'), 2)
        self.assertIn('"reason":"budget"', text)
        self.assertIn('"dropped":10', text)

    def test_a_failed_read_is_counted_and_cited_never_raised(self):
        def script(e):
            rec = {"site": 4, "ring": 0, "ring_seq": 0, "qpc": 10, "tid": 7, "flags": tw.F_READ_FAILED | tw.F_BUF,
                   "args": [1], "buf_addr": 0xDEAD0000, "buf": b""}
            return bytes(e.encode_batch(tw.build_batch(3, 0, 10, (1, 0, 1, 0), [rec]))[0])
        text = self.run_both(script).decode()
        self.assertIn('"read_failed":true', text)
        self.assertIn(str(0xDEAD0000), text)

    def test_wrong_producer_generation_changes_nothing(self):
        for encoder in encoders():
            before = (encoder.head, encoder.count)
            with self.assertRaises(ValueError):
                encoder.encode_batch(tw.build_batch(9, 0, 1, (0, 0, 0, 0), []))
            self.assertEqual((encoder.head, encoder.count), before)

    def test_control_events_share_the_chain(self):
        def script(e):
            a = e.encode_event("core.capture.source", 5, {"source_type": "inprocess-frida", "refused": []})
            b = e.encode_event("core.capture.gap", 6, {"reason": "restart"}, skip=2)
            return bytes(a) + bytes(b)
        self.assertIn(b'"source_seq":3', self.run_both(script))

    def test_randomized_batches_agree(self):
        rng = random.Random(20261101)
        for _ in range(60):
            nxt, records, seqs = 0, [], {}
            for _ in range(rng.randrange(1, 14)):
                ring = rng.randrange(4)
                seqs[ring] = seqs.get(ring, 0) + rng.choice((1, 1, 1, 1, 3))
                path = rng.choice(["C:\\Users\\Ünï\\a.txt", "\\\\.\\NUL", "\\\\?\\C:\\x", "d:/Mixed/Case", "", "😀"])
                kind = rng.choice((1, 2, 3, 4, 5, 9))
                rec = {"site": kind, "ring": ring, "ring_seq": seqs[ring] - 1, "qpc": rng.randrange(10 ** 9), "tid": rng.randrange(1 << 20),
                       "ret_addr": rng.choice((0, rng.getrandbits(47))), "qpc_end": rng.choice((0, rng.randrange(10 ** 9))),
                       "retval": rng.getrandbits(64), "last_error": rng.randrange(1 << 16), "args": [rng.getrandbits(64) for _ in range(rng.randrange(7))],
                       "flags": rng.choice((0, tw.F_RET)) | rng.choice((0, tw.F_WIDE, tw.F_TRUNCATED, tw.F_READ_FAILED)),
                       "buf": wide(path) if rng.random() < 0.6 else bytes(rng.randrange(256) for _ in range(rng.randrange(40))), "buf_addr": rng.getrandbits(47)}
                records.append(rec)
            attempted = sum(seqs.values())
            batch = tw.build_batch(3, nxt, rng.randrange(10 ** 9), (attempted, rng.randrange(3), rng.randrange(3), rng.randrange(2)), records)
            outs = []
            for encoder in encoders(payload_authorized=rng.random() < 0.5):
                outs.append((bytes(encoder.encode_batch(batch)[0]), encoder.head, encoder.count, dict(encoder.stats)))
            self.assertEqual(outs[-1], outs[0])


EVENT_SITES = {
    1: {"name": "CreateFileW", "kind": "open", "module": "KernelBase.dll", "va": 0x7FF800001000, "buf": "id", "preview": 128},
    2: {"name": "CloseHandle", "kind": "close", "module": "KernelBase.dll", "va": 0x7FF800002000},
    3: {"name": "fx_read_config", "kind": "event", "module": "trace_app.exe", "va": 0x140001300, "buf": "id", "buf_arg": 0,
        "event": "app.feature", "hook": "feature-gate",
        "fields": [{"name": "feature", "type": "key", "source": "0"}, {"name": "enabled", "type": "bool", "source": "ret"},
                   {"name": "n", "type": "i32", "source": "1"}, {"name": "name", "type": "string", "source": "0"},
                   {"name": "tag", "type": "hex", "source": "2"}, {"name": "gone", "type": "u8", "source": "7"}]},
    4: {"name": "fx_frame_begin", "kind": "event", "module": "frameloop.exe", "va": 0x140001000, "event": "app.frame", "hook": "frame-begin",
        "fields": [{"name": "frame", "type": "u64", "source": "0"}, {"name": "key", "type": "key", "source": "0"}]},
}


def encoders_for(sites, **options):
    args = ("seg-1", "agent", 3, 4242, sites, KEY, FREQ)
    out = [tw.SegmentEncoder(*args, **options)]
    if HAVE_NATIVE:
        out.append(native.SegmentEncoder(*args, **options))
    return out


class ProfileEvents(unittest.TestCase):
    """Event sites, handle lifetime, deeper call stacks and redacted previews, identical in the Python and Rust encoders."""

    def records(self):
        return [
            {**open_rec(0, 0, 10, "C:\\data\\password=hunter2secret.cfg", 0x88), "stack": [0x7FF800009999, 0x140001234, 0x140005678]},
            {"site": 3, "ring": 0, "ring_seq": 1, "qpc": 20, "tid": 100, "ret_addr": 0x140002000, "qpc_end": 30, "retval": 1,
             "flags": tw.F_RET | tw.F_BUF, "args": [0x5000, 0xFFFFFFFE, 0xBEEF], "buf": b"B\0", "buf_addr": 0x5000},
            {"site": 4, "ring": 1, "ring_seq": 0, "qpc": 25, "tid": 101, "ret_addr": 0x140002100, "args": [41]},
            {"site": 2, "ring": 0, "ring_seq": 2, "qpc": 40, "tid": 100, "ret_addr": 0x7FF800009999, "qpc_end": 41, "retval": 1,
             "flags": tw.F_RET, "args": [0x88]},
            {"site": 2, "ring": 0, "ring_seq": 3, "qpc": 50, "tid": 100, "ret_addr": 0x7FF800009999, "qpc_end": 51, "retval": 1,
             "flags": tw.F_RET, "args": [0x99]},                   # a handle this capture never saw opened
        ]

    def run_all(self):
        batch = tw.build_batch(3, 0, 99, (5, 0, 0, 0), self.records())
        out = []
        for enc in encoders_for(EVENT_SITES):
            lines, _artifacts, _info = enc.encode_batch(batch)
            out.append((bytes(lines), enc))
        return out

    def test_every_encoder_gives_the_same_bytes(self):
        results = self.run_all()
        for lines, _enc in results[1:]:
            self.assertEqual(lines, results[0][0])

    def test_a_record_kept_while_thinned_is_a_sampled_event_in_every_encoder(self):
        records = [{"site": 4, "ring": 1, "ring_seq": 0, "qpc": 25, "tid": 101, "ret_addr": 0x140002100, "args": [41], "flags": tw.F_SAMPLED},
                   {"site": 4, "ring": 1, "ring_seq": 1, "qpc": 26, "tid": 101, "ret_addr": 0x140002100, "args": [42]}]
        batch = tw.build_batch(3, 0, 99, (2, 0, 0, 0), records)
        outputs = []
        for enc in encoders_for(EVENT_SITES):
            lines, _artifacts, _info = enc.encode_batch(batch)
            outputs.append(bytes(lines))
        for lines in outputs[1:]:
            self.assertEqual(lines, outputs[0])
        confidences = [json.loads(line.split(b" ", 1)[1])["confidence"] for line in outputs[0].splitlines() if b"app.frame" in line]
        self.assertEqual(confidences, ["sampled", "exact"])

    def test_a_profile_event_carries_its_declared_fields_and_never_the_text(self):
        events = self.run_all()
        text = events[0][0].decode()
        self.assertNotIn("hunter2", text.replace("***", ""))          # only the redacted preview mentions the word
        self.assertIn('"kind":"app.feature"', text)
        self.assertIn('"kind":"app.frame"', text)
        self.assertIn('"enabled":true', text)
        self.assertIn('"n":-2', text)                                 # i32 sign
        self.assertIn('"tag":"0xbeef"', text)
        self.assertIn('"frame":41', text)
        self.assertIn('"gone":null', text)                            # an argument the record does not have

    def test_handle_lifetime_closes_only_what_was_seen_opened(self):
        for _lines, enc in self.run_all():
            stats = enc.stats() if callable(enc.stats) else enc.stats
            self.assertEqual(stats["close_unknown"], 1)
        text = self.run_all()[0][0].decode()
        self.assertEqual(text.count('"kind":"core.resource.close"'), 1)

    def test_the_call_stack_is_the_whole_unwound_chain(self):
        text = self.run_all()[0][0].decode()
        self.assertIn('"callstack":[%d,%d,%d]' % (0x7FF800009999, 0x140001234, 0x140005678), text)

    def test_a_preview_is_redacted_and_bounded(self):
        text = self.run_all()[0][0].decode()
        self.assertIn('"preview":"C:\\\\data\\\\password=***"', text)
        self.assertIn('"redacted":1', text)

    def test_site_hits_count_the_records_per_site(self):
        for _lines, enc in self.run_all():
            self.assertEqual(dict(enc.site_hits()), {1: 1, 2: 2, 3: 1, 4: 1})

    def test_redaction_rules(self):
        cases = [
            (b"password=hunter2&user=bob", False, "password=***&user=bob"),
            (b"Authorization: Bearer abc123def456ghi789jkl", False, "Authorization: *** ***"),
            (b"GET /index.html?sessionid=12345 HTTP", False, "GET /index.html?sessionid=*** HTTP"),
            (b"key=\"AKIAABCDEFGHIJKLMNOP12\" end", False, "key=\"***\" end"),
            (b"C:\\Users\\me\\Documents\\app.cfg", False, "C:\\Users\\me\\Documents\\app.cfg"),
            ("token : abc".encode("utf-16le") + b"\0\0", True, "token : ***"),
            (b"\x01\x02ok\xff", False, "..ok."),
            (b"A" * 600, False, "A" * 256),
        ]
        for raw, is_wide, want in cases:
            self.assertEqual(tw.redact_preview(raw, is_wide)[0], want, raw)
        self.assertEqual(len(tw.redact_preview(b"x" * 600, False, 1000)[0]), 256)
        self.assertEqual(len(tw.redact_preview(b"x" * 600, False, 10)[0]), 10)

    def test_the_stack_record_layout_round_trips(self):
        batch = tw.build_batch(3, 0, 99, (1, 0, 0, 0), [{**open_rec(0, 0, 10, "a", 1), "stack": [1, 2, 3, 4]}])
        header, back = tw.decode_batch(batch)
        self.assertEqual(back[0]["stack"], [1, 2, 3, 4])
        if HAVE_NATIVE:
            self.assertEqual(native.decode_batch(batch)[1][0]["stack"], [1, 2, 3, 4])


if __name__ == "__main__":
    unittest.main()
