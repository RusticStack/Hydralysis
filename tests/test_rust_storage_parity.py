"""Differential tests: the Python storage layer (durable, storelog) against the Rust crates (hy-core, hy-store) through
the `hydralysis_rs` extension (rust/crates/hy-py). Same inputs, compared outputs and on-disk bytes. Skipped when the
extension is not built. The Python modules here are the reference, so HYDRALYSIS_IMPL must not be `rust` for this file."""

from __future__ import annotations

import json
import os
import random
import tempfile
import unittest
from pathlib import Path

from hydralysis import durable, storelog

try:
    import hydralysis_rs as rs
except ImportError:  # pragma: no cover
    rs = None

SEED = int(os.environ.get("HYDRALYSIS_PARITY_SEED", "20261102"))
ALPHABET = ["a", "b", "é", "ß", "漢", "\u007f", "\n", "\t", "\"", "\\", "\u0001", "😀", " ", "/", "_", "0"]


def rand_text(rng: random.Random) -> str:
    return "".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, 8)))


def rand_value(rng: random.Random, depth: int = 0):
    kinds = ["int", "float", "str", "bool", "none"] + (["list", "dict"] * 2 if depth < 3 else [])
    kind = rng.choice(kinds)
    if kind == "int":
        return rng.choice([0, 1, -1, 7, 2 ** 31, -2 ** 40, 2 ** 53 - 1, 2 ** 63 - 1, rng.randint(-10 ** 9, 10 ** 9)])
    if kind == "float":
        return rng.choice([0.0, -0.0, 0.5, 1.0, 1e16, 1e-5, 1.5e-7, 123456.789, 1e22, 5e-324, rng.random() * 10 ** rng.randint(-8, 20)])
    if kind == "str":
        return rand_text(rng)
    if kind == "bool":
        return rng.random() < 0.5
    if kind == "none":
        return None
    if kind == "list":
        return [rand_value(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    return {rand_text(rng): rand_value(rng, depth + 1) for _ in range(rng.randint(0, 4))}


def rand_object(rng: random.Random) -> dict:
    return {rand_text(rng) or "k": rand_value(rng) for _ in range(rng.randint(1, 5))}


@unittest.skipIf(rs is None or os.environ.get("HYDRALYSIS_IMPL") == "rust", "needs hydralysis_rs and the Python reference")
class Encoding(unittest.TestCase):
    def test_canonical_frame_and_sealed_bytes_are_identical(self):
        rng = random.Random(SEED)
        for _ in range(600):
            value = rand_value(rng)
            self.assertEqual(rs.canonical(json.dumps(value)), durable.canonical(value), value)
            self.assertEqual(rs.frame(json.dumps(value)), durable.frame(value), value)
        for _ in range(300):
            obj = rand_object(rng)
            for indent in (2, 4, None):
                self.assertEqual(rs.dumps_sealed(json.dumps(obj), indent), durable.dumps_sealed(obj, indent), (obj, indent))

    def test_float_repr(self):
        rng = random.Random(SEED + 1)
        for _ in range(3000):
            number = rng.choice([rng.random() * 10 ** rng.randint(-30, 30), float(rng.randint(-10 ** 18, 10 ** 18)), rng.uniform(-1, 1) * 1e-5])
            self.assertEqual(rs.float_repr(number), repr(number))

    def test_refusals_match(self):
        with self.assertRaises(ValueError) as py:
            durable.dumps_sealed({"seal": 1})
        with self.assertRaises(ValueError) as rust:
            rs.dumps_sealed('{"seal": 1}', 2)
        self.assertEqual(str(py.exception), str(rust.exception))


def mutate_log(rng: random.Random, data: bytes) -> bytes:
    action = rng.choice(["cut", "flip", "garbage", "none", "dup", "gaplf"])
    if action == "cut" and data:
        return data[: rng.randint(0, len(data))]
    if action == "flip" and data:
        index = rng.randrange(len(data))
        return data[:index] + bytes([data[index] ^ (1 << rng.randrange(8))]) + data[index + 1:]
    if action == "garbage":
        return data + rng.choice([b"zzzz\n", b"00000000 {\n", b"abc", b"\n\n"])
    if action == "dup" and data:
        return data + data[: rng.randint(0, len(data))]
    if action == "gaplf":
        return data + b"\n" + data
    return data


@unittest.skipIf(rs is None or os.environ.get("HYDRALYSIS_IMPL") == "rust", "needs hydralysis_rs and the Python reference")
class Logs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    @staticmethod
    def status(scan) -> dict:
        return {"records": scan.records, "valid_end": scan.valid_end, "size": scan.size, "torn_tail": scan.torn_tail,
                "corrupt": scan.corrupt}

    def test_scan_of_mutated_logs_is_identical(self):
        rng = random.Random(SEED + 2)
        for case in range(400):
            data = b"".join(durable.frame(rand_value(rng)) for _ in range(rng.randint(0, 6)))
            for _ in range(rng.randint(0, 3)):
                data = mutate_log(rng, data)
            python = self.status(durable.scan_bytes(data))
            rust = json.loads(rs.scan_bytes(data))
            self.assertEqual(python, rust, (case, data))
            target = self.dir / ("log%d" % case)
            target.write_bytes(data)
            start = rng.choice([0, 0, rng.randint(0, len(data))])
            on_disk_py = self.status(durable.scan_file(target, start, True))
            self.assertEqual(on_disk_py, json.loads(rs.scan_file(str(target), start, True)), (case, start))

    def test_append_bytes_and_repairs_are_identical_and_logs_interoperate(self):
        rng = random.Random(SEED + 3)
        for case in range(25):
            py_path, rs_path = self.dir / ("py%d.log" % case), self.dir / ("rs%d.log" % case)
            python_log = durable.AppendLog(py_path)
            records = [rand_object(rng) for _ in range(rng.randint(1, 6))]
            for index, record in enumerate(records):
                offset_py = python_log.append(record)
                offset_rs = rs.log_append(str(rs_path), json.dumps(record))
                self.assertEqual(offset_py, offset_rs)
                if index == 0 and rng.random() < 0.7:  # a torn tail, repaired by the next append of each implementation
                    fragment = durable.frame({"torn": rand_text(rng)})[: rng.randint(1, 12)]
                    for path in (py_path, rs_path):
                        with open(path, "ab") as handle:
                            handle.write(fragment)
            self.assertEqual(py_path.read_bytes(), rs_path.read_bytes())
            repairs_py = [{k: v for k, v in row.items() if k not in ("at", "by")} for row in python_log.repairs()]
            repairs_rs = [{k: v for k, v in row.items() if k not in ("at", "by")} for row in json.loads(rs.log_repairs(str(rs_path)))]
            self.assertEqual(repairs_py, repairs_rs)
            self.assertEqual(python_log.last(), _load(rs.log_last(str(rs_path), False)))
            # Rust-written log appended by Python and the reverse
            python_log.append({"tail": "py"})
            rs.log_append(str(rs_path), json.dumps({"tail": "py"}))
            self.assertEqual(py_path.read_bytes(), rs_path.read_bytes())
            self.assertEqual(durable.AppendLog(rs_path).read(), json.loads(rs.scan_file(str(py_path), 0, True))["records"])

    def test_mid_log_corruption_is_refused_with_the_same_message(self):
        good = durable.frame({"i": 1})
        path = self.dir / "bad.log"
        path.write_bytes(good + b"junk\n" + good)
        with self.assertRaises(ValueError) as py:
            durable.AppendLog(path).append({"i": 2})
        with self.assertRaises(ValueError) as rust:
            rs.log_append(str(path), json.dumps({"i": 2}))
        self.assertEqual(getattr(py.exception, "code", None), "lineage_corrupt")
        self.assertEqual(getattr(rust.exception, "code", None), "lineage_corrupt")
        self.assertEqual(str(py.exception), str(rust.exception))
        self.assertEqual(py.exception.offset, rust.exception.offset)


def _load(text):
    return None if text is None else json.loads(text)


@unittest.skipIf(rs is None or os.environ.get("HYDRALYSIS_IMPL") == "rust", "needs hydralysis_rs and the Python reference")
class SealedRecords(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_write_sealed_bytes_backup_and_reads_are_identical(self):
        rng = random.Random(SEED + 4)
        for case in range(40):
            py_path, rs_path = self.dir / ("py%d.json" % case), self.dir / ("rs%d.json" % case)
            for _ in range(rng.randint(1, 4)):
                value = rand_object(rng)
                self.assertEqual(durable.write_sealed(py_path, value), rs.write_sealed(str(rs_path), json.dumps(value), 2))
            self.assertEqual(py_path.read_bytes(), rs_path.read_bytes())
            self.assertEqual(durable.backup_path(py_path).exists(), durable.backup_path(rs_path).exists())
            if durable.backup_path(py_path).exists():
                self.assertEqual(durable.backup_path(py_path).read_bytes(), durable.backup_path(rs_path).read_bytes())
            record, source = rs.read_sealed_info(str(rs_path))
            self.assertEqual((json.loads(record), source), durable.read_sealed_info(py_path))

    def test_every_damage_reads_the_same(self):
        rng = random.Random(SEED + 5)
        value = {"a": 1, "b": [1, 2, 3], "c": "é"}
        for case in range(120):
            paths = [self.dir / ("py%d.json" % case), self.dir / ("rs%d.json" % case)]
            break_backup = rng.random() < 0.3
            for path in paths:
                durable.write_sealed(path, {"v": 1})
                durable.write_sealed(path, value)
                data = bytearray(path.read_bytes())
                damage = random.Random(case).choice(["cut", "flip", "zero", "text"])
                if damage == "cut":
                    del data[random.Random(case).randint(0, len(data) - 1):]
                elif damage == "flip":
                    data[random.Random(case).randrange(len(data))] ^= 1
                elif damage == "zero":
                    data.clear()
                else:
                    data = bytearray(b"[1, 2]")
                path.write_bytes(bytes(data))
                if break_backup:
                    durable.backup_path(path).write_bytes(b"{broken")
            outcomes = []
            for path, reader in zip(paths, (lambda p: durable.read_sealed_info(p),
                                              lambda p: (lambda r: (json.loads(r[0]), r[1]))(rs.read_sealed_info(str(p))))):
                try:
                    outcomes.append(("ok", reader(path)))
                except ValueError as exc:
                    text = str(exc).replace(str(path.parent), "<dir>").replace(path.name, "<name>")
                    outcomes.append(("err", getattr(exc, "code", None), text))
            self.assertEqual(outcomes[0], outcomes[1], case)

    def test_inspect_file_kinds(self):
        for index, raw in enumerate([None, b"", b"[1]", b"{", b'{"a": 1}', durable.dumps_sealed({"a": 1}),
                                     b'{"a": 1, "seal": {"algo": "md5", "value": "x"}}',
                                     b'{"a": 1, "seal": {"algo": "sha256", "value": "00"}}']):
            path = self.dir / ("i%d.json" % index)
            if raw is not None:
                path.write_bytes(raw)
            for require in (False, True):
                kind, value, reason = durable.inspect_file(path, None, require)
                rkind, rvalue, rreason = rs.inspect_file(str(path), None, require)
                self.assertEqual((kind, value, reason), (rkind, _load(rvalue), rreason))


def bare(record):
    """A store record without the log bookkeeping fields."""
    return {key: value for key, value in record.items()
            if key not in ("log_anchor", "log_prev") and not (key == "scalar" and value is None)}  # a removed field reads as None


def anchors_normalised(data: bytes) -> list:
    """Log rows and the snapshot with their random anchors replaced by their order of appearance."""
    seen: dict = {}

    def name(anchor):
        return seen.setdefault(anchor, "A%d" % len(seen))

    rows = []
    for line in data.split(b"\n"):
        if not line:
            continue
        row = json.loads(line[9:])
        for key in ("a", "prev"):
            if key in row:
                row[key] = name(row[key])
        rows.append(row)
    return rows


def base_store() -> dict:
    return {"version": 3, "edits": [], "reverted": [], "journal": [], "commits": [], "archived": [], "changesets": [], "meta": {"n": 0}}


def step(store: dict, rng: random.Random, index: int) -> dict:
    new = json.loads(json.dumps(store))
    choice = rng.choice(["push", "push", "drop", "set", "meta", "del", "replace_list"])
    field = rng.choice(storelog.LIST_FIELDS)
    if choice == "push":
        new[field] = new[field] + [{"i": index, "t": rand_text(rng)}]
    elif choice == "drop" and new[field]:
        new[field] = new[field][rng.randint(1, len(new[field])):] + [{"i": index}]
    elif choice == "set":
        new["scalar"] = rand_value(rng)
    elif choice == "meta":
        new["meta"] = {"n": index, "x": rand_value(rng)}
    elif choice == "del":
        new.pop("scalar", None)
    else:
        new[field] = [{"r": index}] * rng.randint(0, 3)
    return new


@unittest.skipIf(rs is None or os.environ.get("HYDRALYSIS_IMPL") == "rust", "needs hydralysis_rs and the Python reference")
class StoreLog(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        storelog._CACHE.clear()
        rs.storelog_clear_cache()

    def test_diff_is_identical(self):
        rng = random.Random(SEED + 6)
        store = base_store()
        for index in range(500):
            new = step(store, rng, index)
            self.assertEqual(json.dumps(storelog.diff(store, new)), json.dumps(json.loads(rs.storelog_diff(json.dumps(store), json.dumps(new)))), index)
            store = new if rng.random() < 0.8 else base_store()

    def test_saves_write_the_same_rows_and_snapshots_and_read_back_equal(self):
        rng = random.Random(SEED + 7)
        py_path, rs_path = self.dir / "py.json", self.dir / "rs.json"
        store = base_store()
        for index in range(200):  # crosses SNAPSHOT_EVERY (64) several times: snapshots, trims, prev chaining
            store = step(store, rng, index)
            storelog.save(py_path, store, max_bytes=None, too_large=None)
            rs.storelog_save(str(rs_path), json.dumps(store), None, None)
            if index % 17 == 0:
                self.assertEqual(bare(storelog.read(py_path, durable.read_sealed(py_path))), bare(json.loads(rs.storelog_read(str(rs_path), json.dumps(durable.read_sealed(rs_path)), None))))
        self.assertEqual(anchors_normalised(storelog.log_path(py_path).read_bytes()), anchors_normalised(storelog.log_path(rs_path).read_bytes()))
        for path in (py_path, durable.backup_path(py_path)):
            twin = path.with_name(path.name.replace("py", "rs"))
            left, right = json.loads(path.read_bytes()), json.loads(twin.read_bytes())
            for body in (left, right):
                body.pop("seal"), body.pop("log_anchor"), body.pop("log_prev", None)
            self.assertEqual(left, right)
        self.assertEqual(bare(storelog.read(py_path, durable.read_sealed(py_path))), bare(store))
        self.assertEqual(bare(json.loads(rs.storelog_read(str(rs_path), json.dumps(durable.read_sealed(rs_path)), None))), bare(store))

    def test_python_and_rust_writers_continue_each_others_stores(self):
        rng = random.Random(SEED + 8)
        path = self.dir / "mixed.json"
        store = base_store()
        for index in range(150):
            store = step(store, rng, index)
            if (index // 7) % 2:
                storelog.save(path, store, max_bytes=None, too_large=None)
            else:
                rs.storelog_save(str(path), json.dumps(store), None, None)
            if index % 5 == 0:
                snapshot = durable.read_sealed(path)
                self.assertEqual(bare(json.loads(rs.storelog_read(str(path), json.dumps(snapshot), None))), bare(store), index)
                self.assertEqual(bare(storelog.read(path, snapshot)), bare(store), index)  # chain() mutates its argument
        self.assertEqual(bare(storelog.read(path, durable.read_sealed(path))), bare(store))

    def test_budget_refusal_message_and_nothing_written(self):
        big = base_store()
        big["blob"] = "x" * 5000
        for save in (lambda p: storelog.save(p, big, max_bytes=1000, too_large="store too big"),
                     lambda p: rs.storelog_save(str(p), json.dumps(big), 1000, "store too big")):
            path = self.dir / ("budget%d" % id(save))
            with self.assertRaises(ValueError) as caught:
                save(path)
            self.assertEqual(str(caught.exception), "store too big")
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
