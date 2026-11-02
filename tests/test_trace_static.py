"""Hash registry (15.6), binding tables (15.7), corpus diff and invalidation (15.10) and the 15.3/15.4 reports."""

import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from support import workdir

from hydralysis import profiles, trace_bindings, trace_corpus_diff, trace_hashes, trace_reports
from hydralysis.trace_hashes import Dictionary, HashError, Registry


class HashRegistry(unittest.TestCase):
    def test_builtin_vectors_all_reproduce(self):
        verdict = trace_hashes.verify_builtins()
        self.assertTrue(verdict["ok"], verdict)
        self.assertGreaterEqual(verdict["checked"], 15)

    def test_known_values(self):
        registry = Registry()
        self.assertEqual(registry.compute("fnv1a64", "a"), 0xAF63DC4C8601EC8C)
        self.assertEqual(registry.compute("fnv1a32", "foobar"), 0xBF9CF968)
        self.assertEqual(registry.compute("crc32", "123456789"), 0xCBF43926)
        self.assertEqual(trace_hashes.murmur3_32(b"The quick brown fox jumps over the lazy dog", 0x9747B28C), 0x2FA826CD)
        self.assertEqual(trace_hashes.murmur3_32(b"", 1), 0x514E28B7)
        self.assertEqual(trace_hashes.crc_generic(b"123456789", width=16, poly=0x1021, init=0xFFFF, xorout=0, refin=False, refout=False), 0x29B1)

    def test_a_profile_codec_needs_vectors_it_reproduces(self):
        registry = Registry()
        codec = {"id": "casefold64", "base": "fnv1a", "bits": 64, "fold": "lower",
                 "vectors": [{"input": "A", "output": "0xaf63dc4c8601ec8c"}]}
        algorithm = registry.add_codec(codec)
        self.assertEqual(algorithm("ABC"), registry.compute("fnv1a64", "abc"))
        for bad in ({**codec, "id": "x1", "vectors": []}, {**codec, "id": "x2", "vectors": [{"input": "A", "output": "0x1"}]},
                    {**codec, "id": "fnv1a64"}, {**codec, "id": "x3", "base": "sha1"}, {**codec, "id": "X4"}):
            with self.assertRaises(HashError, msg=bad):
                registry.add_codec(bad)
        self.assertNotIn("x1", registry.algorithms)

    def test_a_custom_basis_and_a_seeded_murmur(self):
        registry = Registry()
        registry.add_codec({"id": "mine", "base": "fnv1a", "bits": 32, "params": {"basis": "0x12345678", "prime": "0x01000193"},
                            "vectors": [{"input": "", "output": "0x12345678"}]})
        registry.add_codec({"id": "seeded", "base": "murmur3_32", "params": {"seed": "0x9747b28c"},
                            "vectors": [{"input": "The quick brown fox jumps over the lazy dog", "output": "0x2fa826cd"}]})
        self.assertEqual(registry.compute("seeded", "The quick brown fox jumps over the lazy dog"), 0x2FA826CD)

    def build(self):
        dictionary = Dictionary(algorithms=["fnv1a64", "fnv1a32", "crc32"])
        names = ["Player", "Enemy", "Weapon", "Door", "Inventory"]
        dictionary.add_lines("\n".join(names) + "\n# comment\n", "fixture word list")
        dictionary.add_manifest(["data/archive/Items.tbl", "data\\archive\\Spells.tbl"], "archive manifest")
        return dictionary

    def test_entries_record_their_sources_and_resolve(self):
        dictionary = self.build()
        answer = dictionary.resolve("fnv1a64", Registry().compute("fnv1a64", "Weapon"))
        self.assertEqual(answer["status"], "resolved")
        self.assertEqual(answer["names"], [{"name": "Weapon", "sources": ["fixture word list"]}])
        self.assertEqual(dictionary.resolve("fnv1a64", 0x1234)["status"], "unknown")
        self.assertEqual(dictionary.resolve("fnv1a64", "0x1234")["hash"], "0x1234")
        with self.assertRaises(HashError):
            dictionary.add("x", " ")
        with self.assertRaises(HashError):
            dictionary.add("", "src")
        with self.assertRaises(HashError):
            dictionary.resolve("nope", 1)

    def test_a_deliberate_collision_is_ambiguous_and_never_resolved(self):
        registry = Registry()
        # a 16-bit CRC collides within a few hundred names; the dictionary treats any algorithm the same way
        registry.add_codec({"id": "crc16", "base": "crc", "bits": 16,
                            "params": {"poly": "0x1021", "init": "0xffff", "xorout": 0, "refin": False, "refout": False},
                            "vectors": [{"input": "123456789", "output": "0x29b1"}]})
        seen, pair = {}, None
        for index in range(5000):
            name = hashlib.sha256(str(index).encode()).hexdigest()[:12]
            value = registry.compute("crc16", name)
            if value in seen:
                pair = (seen[value], name, value)
                break
            seen[value] = name
        self.assertIsNotNone(pair)
        dictionary = Dictionary(registry, algorithms=["crc16"])
        dictionary.add(pair[0], "list one")
        dictionary.add(pair[1], "list two")
        answer = dictionary.resolve("crc16", pair[2])
        self.assertEqual(answer["status"], "ambiguous")
        self.assertEqual([n["name"] for n in answer["names"]], sorted(pair[:2]))
        self.assertEqual(len(dictionary.collisions()), 1)
        note = trace_hashes.annotate_constants(dictionary, [{"value": pair[2], "where": "rva:0x1000"}])[0]
        self.assertEqual(note["status"], "ambiguous")

    def test_annotating_constants(self):
        dictionary = self.build()
        hit = Registry().compute("fnv1a64", "Enemy")
        rows = trace_hashes.annotate_constants(dictionary, [{"value": hit, "where": "rva:0x1010"}, {"value": 0xDEAD, "where": "rva:0x2000"}],
                                               ["fnv1a64"])
        self.assertEqual([r["status"] for r in rows], ["resolved", "unknown"])
        self.assertEqual(rows[0]["answers"][0]["names"][0]["name"], "Enemy")

    def test_an_interpretation_revision_keeps_the_raw_value_and_changes_with_the_dictionary(self):
        dictionary = self.build()
        value = Registry().compute("fnv1a64", "Door")
        events = [{"event_id": "ev_1", "payload": {"record": value, "n": 3}}, {"event_id": "ev_2", "payload": {"record": 0x77}}]
        first = trace_hashes.interpret_events(dictionary, "fnv1a64", events, ["record"])
        self.assertEqual([a["status"] for a in first["annotations"]], ["resolved", "unknown"])
        self.assertEqual(first["annotations"][0]["raw"], "0x%x" % value)
        self.assertTrue(first["interpretation"]["raw_preserved"])
        self.assertEqual(events[0]["payload"]["record"], value)
        again = trace_hashes.interpret_events(dictionary, "fnv1a64", events, ["record"])
        self.assertEqual(first["interpretation"]["revision"], again["interpretation"]["revision"])
        dictionary.add("Window", "later list")
        changed = trace_hashes.interpret_events(dictionary, "fnv1a64", events, ["record"])
        self.assertNotEqual(first["interpretation"]["revision"], changed["interpretation"]["revision"])

    def test_corpus_names_feed_the_dictionary(self):
        with workdir("hash-corpus") as folder:
            path = Path(folder) / "types.jsonl"
            path.write_text("\n".join(json.dumps(r) for r in [
                {"kind": "struct", "name": "Actor", "size": 8, "fields": [{"name": "health", "offset": 0, "type": "int32"}]},
                {"kind": "enum", "name": "Mode", "size": 4, "members": [["Idle", 0], ["Run", 1]]}]) + "\n", "utf-8")
            dictionary = Dictionary(algorithms=["fnv1a64"])
            self.assertEqual(dictionary.add_corpus(path), 5)
            answer = dictionary.resolve("fnv1a64", Registry().compute("fnv1a64", "health"))
            self.assertEqual(answer["names"][0]["sources"], ["type corpus types.jsonl line 1"])

    def test_a_name_search_finds_the_code_that_uses_its_hash(self):
        registry = Registry()
        value = registry.compute("fnv1a64", "Inventory")
        code = b"\x90" * 8 + b"\x48\xb8" + struct.pack("<Q", value) + b"\xc3" + b"\x90" * 8
        data = b"\x00" * 16 + struct.pack("<Q", value)
        raw = code + data

        def section(name, rva, flags, start, size):
            return SimpleNamespace(Name=name.ljust(8, b"\0"), VirtualAddress=rva, PointerToRawData=start, SizeOfRawData=size, Characteristics=flags)

        image = SimpleNamespace(data=raw, sections=[section(b".text", 0x1000, 0x60000020, 0, len(code)),
                                                    section(b".data", 0x2000, 0xC0000040, len(code), len(data))],
                                _bounds=lambda rva: (0x1000, 0x1020) if 0x1000 <= rva < 0x1020 else None)
        dictionary = Dictionary(algorithms=["fnv1a64", "crc32"])
        dictionary.add("Inventory", "word list")
        result = trace_hashes.find_name_users(dictionary, "Inventory", image, algorithms=["fnv1a64"])
        self.assertEqual([(h["section"], h["rva"], h["context"]) for h in result["hits"]],
                         [(".text", "rva:0x100a", "code-immediate"), (".data", "rva:0x2010", "data")])
        self.assertEqual(result["hits"][0]["function"], "rva:0x1000")
        self.assertEqual(result["algorithms"][0]["status"], "resolved")
        self.assertFalse(result["truncated"])
        self.assertEqual(len(trace_hashes.find_name_users(dictionary, "Inventory", image, algorithms=["fnv1a64"], limit=1)["hits"]), 1)


class Memory:
    """A tiny flat image: bytes by RVA, with the interface of pe.Image that the binding code reads."""

    def __init__(self, base=0x140000000):
        self.base = base
        self.cells = {}

    def put(self, rva, data):
        for offset, byte in enumerate(data):
            self.cells[rva + offset] = byte

    def read_rva(self, rva, size):
        if any(rva + i not in self.cells for i in range(size)):
            raise ValueError("not in a section")
        return bytes(self.cells[rva + i] for i in range(size))

    def string_at(self, rva, limit=80):
        out = bytearray()
        while rva in self.cells and self.cells[rva] and len(out) < limit:
            out.append(self.cells[rva])
            rva += 1
        return out.decode("ascii") if out else None


NATIVES = ["print", "spawn", "despawn", "get_health", "set_health", "play_sound", "load_level", "rand", "time", "quit"]
CALLED = [("log", 0x1200, 1), ("wait", 0x1210, 2)]
STRIDE = 24


def vm_image():
    memory = Memory()
    memory.put(0x1000, b"\x90" * 0x400)                      # code: natives at 0x1000 + 0x10 * i
    names_at = 0x3000
    cursor = names_at
    name_rva = {}
    for name in NATIVES + [c[0] for c in CALLED]:
        memory.put(cursor, name.encode() + b"\0")
        name_rva[name] = cursor
        cursor += len(name) + 1
    for index, name in enumerate(NATIVES):
        row = 0x2000 + index * STRIDE
        memory.put(row, struct.pack("<QQI", memory.base + name_rva[name], memory.base + 0x1000 + 0x10 * index, index % 4) + b"\0" * 4)
    memory.put(0x2000 + len(NATIVES) * STRIDE, b"\0" * STRIDE)        # null terminator row
    # one native is reached through a jmp thunk to an implementation
    memory.put(0x1000 + 0x10 * 3, b"\xe9" + struct.pack("<i", 0x1300 - (0x1000 + 0x10 * 3 + 5)))
    memory.put(0x1300, b"\x55\x8b\xec")
    return memory, name_rva


TABLE_SPEC = {"id": "minivm-table", "kind": "table", "table_rva": 0x2000, "stride": STRIDE, "name_offset": 0, "fn_offset": 8,
              "argc_offset": 16, "argc_size": 4, "count": None}
CALL_SPEC = {"id": "minivm-register", "kind": "call", "register": "reg", "name_arg": 1, "fn_arg": 2, "argc_arg": 3}


def call_sites(name_rva, memory):
    return [{"site": "rva:0x%x" % (0x1100 + 0x20 * i), "args": [
        {"index": 1, "rva": name_rva[name]}, {"index": 2, "constant": memory.base + fn}, {"index": 3, "constant": argc}]}
        for i, (name, fn, argc) in enumerate(CALLED)]


class Bindings(unittest.TestCase):
    def test_twelve_natives_are_recovered_ten_from_the_table_and_two_from_calls(self):
        memory, name_rva = vm_image()
        table = trace_bindings.collect(memory, [TABLE_SPEC, CALL_SPEC], {"minivm-register": call_sites(name_rva, memory)})
        self.assertEqual(table["counts"], {"rows": 12, "resolved": 12, "unresolved": 0})
        rows = {row["script_name"]: row for row in table["rows"]}
        self.assertEqual(set(rows), set(NATIVES) | {"log", "wait"})
        self.assertEqual(rows["spawn"]["native_rva"], "rva:0x1010")
        self.assertEqual(rows["spawn"]["argc"], 1)
        self.assertEqual(rows["wait"]["argc"], 2)
        self.assertEqual(rows["log"]["native_rva"], "rva:0x1200")
        self.assertEqual(table["tables"][0]["ended"], "null-name")
        self.assertTrue(rows["get_health"]["thunk"])
        self.assertEqual(rows["get_health"]["implementation_rva"], "rva:0x1300")
        self.assertFalse(rows["print"]["thunk"])
        self.assertTrue(all("minivm" in row["source"] for row in rows.values()))
        self.assertEqual(table["conflicting_names"], {})

    def test_an_unreadable_row_is_unresolved_with_its_reason(self):
        memory, _ = vm_image()
        memory.put(0x2000, struct.pack("<QQI", memory.base + 0x9999, memory.base + 0xF0000, 1) + b"\0" * 4)
        rows = trace_bindings.extract_table(memory, TABLE_SPEC)["rows"]
        self.assertEqual(rows[0]["status"], "unresolved")
        self.assertEqual(len(rows[0]["unresolved"]), 2)
        self.assertEqual(rows[1]["status"], "resolved")

    def test_a_table_that_runs_off_the_image_ends_there_and_says_so(self):
        memory, _ = vm_image()
        spec = {**TABLE_SPEC, "table_rva": 0x2000 + 9 * STRIDE, "count": 3}
        result = trace_bindings.extract_table(memory, spec)
        self.assertEqual(len(result["rows"]), 2)
        self.assertEqual(result["ended"], "table-ends-outside-the-image")

    def test_a_registration_whose_arguments_were_not_constant_is_unresolved(self):
        sites = [{"site": "rva:0x1100", "args": [{"index": 1}, {"index": 2, "constant": 0x140001200}]}]
        memory, _ = vm_image()
        row = trace_bindings.bindings_from_call_sites(CALL_SPEC, sites, memory)["rows"][0]
        self.assertEqual(row["status"], "unresolved")
        self.assertIn("argument 1 (name)", row["unresolved"][0])

    def test_the_corpus_and_the_cross_layer_edges_cite_their_source(self):
        memory, name_rva = vm_image()
        table = trace_bindings.collect(memory, [TABLE_SPEC, CALL_SPEC], {"minivm-register": call_sites(name_rva, memory)})
        records, body = trace_bindings.to_corpus(table, build_sha256="ab" * 32, source="fixture minivm")
        self.assertEqual(len(records), 12)
        health = next(r for r in records if r["name"] == "vm_native_get_health")
        self.assertEqual(health["address"], "rva:0x1300")
        self.assertIn("table minivm-table", health["comment"])
        self.assertIn("(undefined8 arg0, undefined8 arg1, undefined8 arg2)", health["signature"])
        self.assertEqual(body["counts"]["resolved"], 12)
        self.assertEqual(len(body["content_sha256"]), 64)
        edge = next(e for e in trace_bindings.cross_layer_edges(table) if e["path"][0] == "script:get_health")
        self.assertEqual(edge["path"], ["script:get_health", "rva:0x1030", "rva:0x1300"])

    def test_a_traced_script_call_links_to_its_native_event(self):
        memory, name_rva = vm_image()
        table = trace_bindings.collect(memory, [TABLE_SPEC, CALL_SPEC], {"minivm-register": call_sites(name_rva, memory)})
        events = [
            {"event_id": "ev_1", "seq": 1, "thread_gen": 1, "kind": "app.script.call", "payload": {"script_function": "get_health"}},
            {"event_id": "ev_2", "seq": 2, "thread_gen": 2, "kind": "core.function.enter", "rva": 0x1300},       # other thread
            {"event_id": "ev_3", "seq": 3, "thread_gen": 1, "kind": "core.function.enter", "rva": 0x1300},
            {"event_id": "ev_4", "seq": 4, "thread_gen": 1, "kind": "app.script.call", "payload": {"script_function": "rand"}},
            {"event_id": "ev_5", "seq": 5, "thread_gen": 1, "kind": "app.script.call", "payload": {"script_function": "mystery"}},
        ]
        linked = trace_bindings.link_events(events, table)
        self.assertEqual([(l["from"], l["to"]) for l in linked["links"]], [("ev_1", "ev_3")])
        self.assertEqual(linked["links"][0]["relation"], "observed-call")
        self.assertEqual({u["event_id"]: u["reason"][:6] for u in linked["unlinked"]}, {"ev_4": "no mat", "ev_5": "not in"})

    def test_a_profile_may_declare_the_layouts(self):
        text = profiles.BASELINE.read_text("utf-8") + """
[[bindings]]
id = "minivm-table"
kind = "table"
table_rva = "0x2000"
stride = 24
name_offset = 0
fn_offset = 8
argc_offset = 16
[[bindings]]
id = "minivm-register"
kind = "call"
register = "plugin-load"
name_arg = 1
fn_arg = 2
argc_arg = 3
"""
        profile = profiles.load_text(text)
        self.assertEqual([b["id"] for b in profile.data["bindings"]], ["minivm-table", "minivm-register"])
        self.assertEqual(profile.data["bindings"][0]["table_rva"], 0x2000)
        with self.assertRaises(profiles.ProfileError):
            profiles.load_text(profiles.BASELINE.read_text("utf-8") + '\n[[bindings]]\nid = "t"\nkind = "table"\n')
        with self.assertRaises(profiles.ProfileError):
            profiles.load_text(profiles.BASELINE.read_text("utf-8") + '\n[[bindings]]\nid = "c"\nkind = "call"\nregister = "nope"\nname_arg = 0\nfn_arg = 1\n')


def corpus(*records):
    return trace_corpus_diff.load_corpus(list(records))


def build(with_field=False, moved=False, removed=False):
    fields = [{"name": "id", "offset": 0, "type": "uint32"}, {"name": "health", "offset": 4, "type": "int32"},
              {"name": "mana", "offset": 8, "type": "int32"}]
    if with_field:  # an inserted field shifts the ones after it
        fields = [fields[0], {"name": "armor", "offset": 4, "type": "int32"},
                  {"name": "health", "offset": 8, "type": "int32"}, {"name": "mana", "offset": 12, "type": "int32"}]
    records = [{"kind": "struct", "name": "Actor", "size": 16 if with_field else 12, "fields": fields},
               {"kind": "enum", "name": "Mode", "size": 4, "members": [["Idle", 0], ["Run", 1]]},
               {"kind": "function", "name": "Actor_Update", "address": "rva:0x2200" if moved else "rva:0x2000"},
               {"kind": "function", "name": "Actor_Hit", "address": "rva:0x2100"}]
    if not removed:
        records.append({"kind": "function", "name": "Actor_Legacy", "address": "rva:0x2300"})
    return corpus(*records)


class CorpusDiff(unittest.TestCase):
    def test_the_diff_names_the_inserted_field_the_moved_and_the_removed_function(self):
        diff = trace_corpus_diff.diff_corpora(build(), build(with_field=True, moved=True, removed=False))
        changes = {(c["field"], c["change"]) for c in diff["fields"]}
        self.assertEqual(changes, {("armor", "added"), ("health", "moved"), ("mana", "moved")})
        self.assertEqual(diff["types"]["resized"], [{"type": "Actor", "change": "resized", "a": 12, "b": 16}])
        self.assertEqual(diff["functions"]["moved"], [{"name": "Actor_Update", "a": "rva:0x2000", "b": "rva:0x2200"}])
        removed = trace_corpus_diff.diff_corpora(build(), build(removed=True))
        self.assertEqual(removed["functions"]["removed"], ["Actor_Legacy"])

    def test_enum_members_and_a_hash_matched_rename(self):
        a = corpus({"kind": "enum", "name": "Mode", "size": 4, "members": [["Idle", 0], ["Run", 1], ["Hide", 2]], "hash": 77},
                   {"kind": "struct", "name": "OldName", "size": 4, "fields": [], "hash": 5})
        b = corpus({"kind": "enum", "name": "Mode", "size": 4, "members": [["Idle", 0], ["Run", 5], ["Swim", 2]], "hash": 77},
                   {"kind": "struct", "name": "NewName", "size": 4, "fields": [], "hash": 5})
        diff = trace_corpus_diff.diff_corpora(a, b)
        self.assertEqual({(c["member"], c["change"]) for c in diff["enum_members"]},
                         {("Run", "value_changed"), ("Hide", "removed"), ("Swim", "added")})
        self.assertEqual(diff["types"]["renamed"], [{"from": "OldName", "to": "NewName", "basis": "hash 5"}])
        self.assertEqual((diff["types"]["added"], diff["types"]["removed"]), ([], []))

    def dependents(self):
        return [
            {"id": "codec:actor", "kind": "codec", "refs": [{"type": "Actor", "field": "id"}, {"type": "Actor", "field": "health"}]},
            {"id": "codec:ids", "kind": "codec", "refs": [{"type": "Actor", "field": "id"}]},
            {"id": "hook:update", "kind": "hook", "refs": [{"function": "Actor_Update", "rva": "0x2000", "prologue": "55 8B EC"}]},
            {"id": "claim:hit", "kind": "evidence", "refs": [{"function": "Actor_Hit", "rva": "0x2100"}]},
            {"id": "claim:legacy", "kind": "evidence", "refs": [{"function": "Actor_Legacy", "rva": "0x2300"}]},
            {"id": "claim:by-address", "kind": "evidence", "refs": [{"rva": "0x2300"}]},
            {"id": "overlay:mode", "kind": "overlay", "refs": [{"enum": "Mode", "member": "Run"}]},
            {"id": "assert:gone", "kind": "assertion", "refs": [{"type": "Vanished", "field": "x"}]},
        ]

    def report(self, readers=None):
        a, b = build(), build(with_field=True, moved=True, removed=True)
        return trace_corpus_diff.invalidation_report(a, b, self.dependents(), readers=readers, build_a="A", build_b="B")

    def test_acceptance_moved_candidate_unplaced_and_everything_else_carried(self):
        a_bytes = {0x2100: b"\x55\x8b\xec\x83\xec\x10\x90\x90" * 2}
        readers = (lambda address, size: a_bytes.get(address), lambda address, size: a_bytes.get(address))
        report = self.report(readers)
        status = {item["id"]: item["status"] for item in report["items"]}
        self.assertEqual(status, {"codec:actor": "moved", "codec:ids": "carried", "hook:update": "candidate",
                                  "claim:hit": "carried", "claim:legacy": "unplaced", "claim:by-address": "unplaced",
                                  "overlay:mode": "carried", "assert:gone": "unplaced"})
        self.assertEqual(report["promoted"], 0)
        self.assertIn("Nothing is promoted", report["policy"])
        self.assertEqual(report["counts"], {"carried": 3, "candidate": 1, "moved": 1, "unplaced": 3})
        self.assertEqual(report["moved_layouts"][0]["dependents"], ["codec:actor"])
        self.assertEqual([item["status"] for item in report["items"]], sorted((item["status"] for item in report["items"]),
                         key=lambda s: -trace_corpus_diff.PRIORITY[s]))

    def test_a_function_is_never_carried_without_bytes_of_both_builds(self):
        report = self.report(readers=None)
        status = {item["id"]: item["status"] for item in report["items"]}
        self.assertEqual(status["claim:hit"], "candidate")
        self.assertIn("no bytes", report["items"][[i["id"] for i in report["items"]].index("claim:hit")]["reasons"][0]["why"])

    def test_changed_bytes_at_the_same_address_are_a_candidate_not_carried(self):
        old, new = {0x2100: b"\x55" * 16}, {0x2100: b"\x56" * 16}
        report = self.report((lambda a, s: old.get(a), lambda a, s: new.get(a)))
        self.assertEqual({i["id"]: i["status"] for i in report["items"]}["claim:hit"], "candidate")

    def test_profile_and_ledger_adapters(self):
        profile = profiles.load_text(profiles.BASELINE.read_text("utf-8").replace("limit = 50", "limit = 50") + """
[[codecs]]
id = "actor"
base = "layout"
struct = "Actor"
fields = [{name = "id", offset = 0, type = "u32"}, {name = "health", offset = 4, type = "i32"}]
""")
        items = trace_corpus_diff.dependents_from_profile(profile)
        ids = {item["id"] for item in items}
        self.assertEqual(ids, {"hook:" + hook["id"] for hook in profile.data["hooks"]} | {"codec:actor"})
        self.assertIn("hook:frame-begin", ids)
        codec = next(item for item in items if item["id"] == "codec:actor")
        report = trace_corpus_diff.invalidation_report(build(), build(with_field=True), [codec])
        self.assertEqual(report["items"][0]["status"], "moved")
        claims = trace_corpus_diff.dependents_from_claims([{"evidence_id": "ev_x", "name": "Actor_Hit", "address": "0x2100", "prologue": "55"}])
        self.assertEqual(claims[0]["refs"][0]["function"], "Actor_Hit")
        mapped = trace_corpus_diff.dependents_from_address_map([{"name": "Actor_Hit", "rva": "0x2100"}])
        self.assertEqual(mapped[0]["kind"], "address_map")

    def test_loading_from_a_file_and_a_bad_line(self):
        with workdir("corpus-diff") as folder:
            path = Path(folder) / "a.jsonl"
            path.write_text(json.dumps({"kind": "struct", "name": "S", "size": 4, "fields": []}) + "\n", "utf-8")
            self.assertIn("S", trace_corpus_diff.load_corpus(path)["types"])
            path.write_text("{not json}\n", "utf-8")
            with self.assertRaises(trace_corpus_diff.CorpusError):
                trace_corpus_diff.load_corpus(path)


def write(frame, event_id, phase, site, value, ours, seq, thread=1, role="main", field="Actor.speed"):
    return {"event_id": event_id, "kind": "core.state.write", "frame": frame, "phase": phase, "function": site, "seq": seq,
            "thread_gen": thread, "role": role, "ours": ours, "payload": {"state_key": field, "value": value}}


def read(frame, event_id, phase, value, seq, thread=1, field="Actor.speed", function="Render"):
    return {"event_id": event_id, "kind": "core.state.read", "frame": frame, "phase": phase, "function": function, "seq": seq,
            "thread_gen": thread, "role": "main", "payload": {"state_key": field, "value": value}}


PHASES = ["input", "update", "late", "render"]


def frames(count, overwritten_every=1, gap=None):
    events = []
    for frame in range(count):
        base = frame * 10
        events.append(write(frame, "w%d" % frame, "update", "OurHook", 9, True, base + 1))
        if frame % overwritten_every == 0:
            events.append(write(frame, "o%d" % frame, "late", "HostAnimator::Tick", 1, False, base + 2))
        events.append(read(frame, "r%d" % frame, "render", 1 if frame % overwritten_every == 0 else 9, base + 3))
    return events


class Reports(unittest.TestCase):
    def test_a_later_stage_overwrites_on_most_frames_and_the_report_names_it(self):
        events = frames(40, overwritten_every=1)
        report = trace_reports.write_survival(events, field="Actor.speed", consumer="Render", phases=PHASES)
        self.assertEqual(report["verdicts"], {"survived": 0, "overwritten": 40, "consumer read before write": 0, "unknown": 0})
        self.assertEqual(report["overwriters"], [{"site": "HostAnimator::Tick", "frames": 40}])
        self.assertEqual(report["summary"], "40 of 40 frames overwritten by one site")
        self.assertEqual(report["ratios_ppm"]["overwritten"], 1_000_000)
        self.assertEqual(report["claim"], "all_frames_decided")
        self.assertEqual(report["per_frame"][0]["overwritten_by"], "HostAnimator::Tick")
        self.assertEqual(report["per_frame"][0]["produced_by"], "o0")
        self.assertEqual(report["representatives"]["overwritten"], [0, 1, 2])

    def test_removing_the_overwrite_turns_every_frame_to_survived(self):
        events = [e for e in frames(40) if not e["event_id"].startswith("o")]
        report = trace_reports.write_survival(events, field="Actor.speed", consumer="Render", phases=PHASES)
        self.assertEqual(report["verdicts"]["survived"], 40)
        self.assertIsNone(report["summary"])
        self.assertEqual(report["ratios_ppm"]["survived"], 1_000_000)

    def test_a_mixed_run_gives_the_ratio(self):
        events = frames(10, overwritten_every=3)
        report = trace_reports.write_survival(events, field="Actor.speed", consumer="Render", phases=PHASES)
        self.assertEqual(report["verdicts"]["overwritten"], 4)
        self.assertEqual(report["verdicts"]["survived"], 6)
        self.assertEqual(report["summary"], "4 of 10 frames overwritten by one site")
        self.assertEqual(report["ratios_ppm"]["overwritten"], 400000)

    def test_a_consumer_that_reads_before_our_write(self):
        events = [read(0, "r0", "input", 1, 1), write(0, "w0", "update", "OurHook", 9, True, 2)]
        report = trace_reports.write_survival(events, field="Actor.speed", consumer="Render", phases=PHASES)
        self.assertEqual(report["verdicts"]["consumer read before write"], 1)

    def test_unknown_is_never_pass_gaps_missing_reads_and_unordered_writes(self):
        events = frames(3)
        gapped = trace_reports.write_survival(events, field="Actor.speed", consumer="Render", phases=PHASES, gaps=[{"frame": 1}])
        self.assertEqual(gapped["per_frame"][1]["verdict"], "unknown")
        self.assertIn("capture gap", gapped["per_frame"][1]["reason"])
        self.assertEqual(gapped["claim"], "may_not_be_complete")
        no_read = [e for e in events if e["kind"] != "core.state.read"]
        self.assertEqual(trace_reports.write_survival(no_read, field="Actor.speed", consumer="Render", phases=PHASES)["verdicts"]["unknown"], 3)
        # two writes in the same stage on different threads: their order is not established
        rival = [e for e in events if not e["event_id"].startswith("o")] + [write(0, "x0", "update", "OtherThread", 5, False, 99, thread=7)]
        report = trace_reports.write_survival(rival, field="Actor.speed", consumer="Render", phases=PHASES)
        self.assertEqual(report["per_frame"][0]["verdict"], "unknown")
        self.assertIn("order not established", report["per_frame"][0]["reason"])
        # without phases and on different threads nothing is ordered
        bare = trace_reports.write_survival([write(0, "w", "u", "Our", 9, True, 1, thread=1), read(0, "r", "r", 9, 2, thread=2)],
                                            field="Actor.speed", consumer="Render")
        self.assertEqual(bare["per_frame"][0]["verdict"], "unknown")

    def test_the_report_is_deterministic(self):
        events = frames(12, overwritten_every=2)
        one = trace_reports.write_survival(events, field="Actor.speed", consumer="Render", phases=PHASES)
        two = trace_reports.write_survival(list(reversed(events)), field="Actor.speed", consumer="Render", phases=PHASES)
        self.assertEqual(json.dumps(one, sort_keys=True), json.dumps(two, sort_keys=True))

    def overload_events(self):
        def w(event_id, function, stack, frame=0):
            return {"event_id": event_id, "kind": "core.state.write", "frame": frame, "function": function, "stack": stack,
                    "va": 0x1000, "payload": {"state_key": "Actor.hp"}}
        return [w("w1", "Actor::SetHp(int)", ["Caller"]), w("w2", "Actor::SetHp(float)", ["VCaller"], frame=1),
                w("w3", "Actor::SetHp(int)", ["Caller"], frame=2), w("w4", "Wrapper", ["Actor::SetHp(int)", "Caller"], frame=3)]

    def test_hooking_one_overload_reports_the_other_as_a_bypass_with_its_path_and_class(self):
        edges = trace_reports.observed_edges([
            {"event_id": "c1", "kind": "core.function.enter", "frame": 1, "payload": {"site": "rva:0x500", "target": "Actor::SetHp(float)",
                                                                                      "receiver_class": "Hero", "slot": 3}},
            {"event_id": "c2", "kind": "core.function.enter", "frame": 2, "payload": {"site": "rva:0x500", "target": "Actor::SetHp(float)",
                                                                                      "receiver_class": "Hero", "slot": 3}}],
            static_candidates={"rva:0x500": ["Actor::SetHp(float)", "Actor::SetHp(double)"]})
        self.assertEqual(edges["observed"][0]["count"], 2)
        self.assertEqual(edges["observed"][0]["frames"], [1, 2])
        self.assertEqual(edges["unobserved_candidates"], [{"site": "rva:0x500", "target": "Actor::SetHp(double)", "status": "may call",
                                                           "basis": "static candidate (vcalls); never observed"}])
        report = trace_reports.hook_bypass(self.overload_events(), hook="Actor::SetHp(int)", field="Actor.hp", observed=edges["observed"])
        self.assertEqual((report["writes_observed"], report["through_hook"], report["bypassed"]), (4, 3, 1))
        bypass = report["bypasses"][0]
        self.assertEqual((bypass["class"], bypass["event_id"], bypass["receiver_class"], bypass["via"]),
                         ("different-slot", "w2", "Hero", "rva:0x500"))
        self.assertEqual(bypass["path"], ["Actor::SetHp(float)", "VCaller"])
        self.assertEqual(report["verdict"], "hook_bypassed")
        sibling = trace_reports.hook_bypass(self.overload_events(), hook="Actor::SetHp(int)", field="Actor.hp",
                                            siblings=["Actor::SetHp(float)"])
        self.assertEqual(sibling["by_class"], {"sibling-overload": 1})

    def test_no_bypass_and_no_writes_are_different_answers(self):
        clean = [e for e in self.overload_events() if e["function"] != "Actor::SetHp(float)"]
        self.assertEqual(trace_reports.hook_bypass(clean, hook="Actor::SetHp(int)", field="Actor.hp")["verdict"], "hook_covers_observed_writes")
        self.assertEqual(trace_reports.hook_bypass([], hook="x", field="Actor.hp")["verdict"], "no_writes_observed")
        copy = [{"event_id": "w9", "kind": "core.state.write", "function": None, "va": 0x77, "payload": {"state_key": "Actor.hp"}}]
        self.assertEqual(trace_reports.hook_bypass(copy, hook="x", field="Actor.hp")["bypasses"][0]["class"], "inlined-copy")

    def test_the_discovery_report_keeps_three_kinds_of_answer_apart(self):
        report = trace_reports.discovery_report(exercised=[{"key": "a"}, {"key": "b"}], candidates=[{"key": "b"}, {"key": "c"}],
                                                observation_gaps=[{"interval": [1, 2], "reason": "observer-inactive"}])
        self.assertEqual(report["exercised_behavior"]["count"], 2)
        self.assertEqual([i["key"] for i in report["unobserved_candidates"]["items"]], ["c"])
        self.assertEqual(report["observation_gaps"]["count"], 1)


if __name__ == "__main__":
    unittest.main()
