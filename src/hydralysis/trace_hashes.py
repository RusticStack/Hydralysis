"""Hash-keyed identities, resolved (semantic trace spec 15.6).

Engines name resources, records and types by hashed strings. This module holds

* a **registry** of hash algorithms: FNV-1 and FNV-1a (32 and 64 bit), CRC-32 (IEEE), Murmur3 x86 32, and profile
  codecs. A profile codec is a *parameterised* algorithm (an FNV with its own basis and prime, a CRC with its own
  polynomial, a Murmur with a seed, plus case folding and an encoding) and is refused unless it reproduces the test
  vectors its profile gives;
* a **dictionary** of names, each entry recording where it came from. Two different names with one hash under one
  algorithm are reported `ambiguous`; nothing is ever resolved by picking one;
* **static use**: constants in an image that match a dictionary entry, and the reverse (a name to the constants and
  the code sites that carry its hash);
* **trace use**: resolving hashed ids in event payloads at query time as an **interpretation revision**
  (`interpretation()`), which keeps the raw value and is identified by the dictionary and algorithm it used.

Pure Python, stdlib only. Hashes are integers; text forms are lowercase `0x...` without padding.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import zlib
from pathlib import Path

from hydralysis import trace_native

MAX_NAME = 512
MAX_ENTRIES = 5_000_000
CASE_FOLDS = ("none", "lower", "upper")
ENCODINGS = ("utf-8", "utf-16le", "ascii", "latin-1")


class HashError(ValueError):
    """A codec or a vector that is wrong, with a stable code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _routed(name: str):
    """The Rust twin of a function of this module (HYDRALYSIS_IMPL=rust), else None."""
    return trace_native.function(name)


# ---- primitive algorithms -------------------------------------------------------------------------------------

def fnv(data: bytes, bits: int, *, variant: str = "1a", basis: int | None = None, prime: int | None = None) -> int:
    routed = _routed("fnv")
    if routed is not None and isinstance(data, (bytes, bytearray)) and isinstance(bits, int) and isinstance(variant, str):
        try:
            return routed(bytes(data), bits, variant, basis, prime)
        except trace_native.native().TraceHashError as exc:
            raise HashError(*exc.args) from None
        except trace_native.native().TraceFallback:
            pass
    defaults = {32: (0x811C9DC5, 0x01000193), 64: (0xCBF29CE484222325, 0x100000001B3)}
    if bits not in defaults:
        raise HashError("bad_width", "FNV is defined here for 32 and 64 bits")
    if variant not in ("1", "1a"):
        raise HashError("bad_variant", "FNV variant is 1 or 1a")
    value = defaults[bits][0] if basis is None else basis
    step = defaults[bits][1] if prime is None else prime
    mask = (1 << bits) - 1
    for byte in data:
        if variant == "1a":
            value = ((value ^ byte) * step) & mask
        else:
            value = ((value * step) & mask) ^ byte
    return value


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def crc_generic(data: bytes, *, width: int = 32, poly: int = 0x04C11DB7, init: int = 0xFFFFFFFF, xorout: int = 0xFFFFFFFF,
                refin: bool = True, refout: bool = True) -> int:
    """A bitwise CRC with the usual Rocksoft parameters, for a profile whose CRC is not the IEEE one."""
    routed = _routed("crc_generic")
    if routed is not None and isinstance(data, (bytes, bytearray)) and isinstance(width, int):
        try:
            return routed(bytes(data), width, poly, init, xorout, bool(refin), bool(refout))
        except trace_native.native().TraceHashError as exc:
            raise HashError(*exc.args) from None
        except trace_native.native().TraceFallback:
            pass
    if not 8 <= width <= 64:
        raise HashError("bad_width", "CRC width is 8..64")
    top, mask = 1 << (width - 1), (1 << width) - 1

    def reflect(value: int, bits: int) -> int:
        return int(format(value, "0%db" % bits)[::-1], 2)

    register = init & mask
    for byte in data:
        if refin:
            byte = reflect(byte, 8)
        register ^= byte << (width - 8)
        for _ in range(8):
            register = ((register << 1) ^ poly) & mask if register & top else (register << 1) & mask
    if refout:
        register = reflect(register, width)
    return (register ^ xorout) & mask


def murmur3_32(data: bytes, seed: int = 0) -> int:
    routed = _routed("murmur3_32")
    if routed is not None and isinstance(data, (bytes, bytearray)) and isinstance(seed, int):
        try:
            return routed(bytes(data), seed)
        except trace_native.native().TraceFallback:
            pass
    c1, c2, mask = 0xCC9E2D51, 0x1B873593, 0xFFFFFFFF
    value = seed & mask
    blocks = len(data) // 4
    for (word,) in struct.iter_unpack("<I", data[:blocks * 4]):
        word = (word * c1) & mask
        word = ((word << 15) | (word >> 17)) & mask
        word = (word * c2) & mask
        value ^= word
        value = ((value << 13) | (value >> 19)) & mask
        value = (value * 5 + 0xE6546B64) & mask
    tail, word = data[blocks * 4:], 0
    for index in range(len(tail) - 1, -1, -1):
        word = (word << 8) | tail[index]
    if tail:
        word = (word * c1) & mask
        word = ((word << 15) | (word >> 17)) & mask
        word = (word * c2) & mask
        value ^= word
    value ^= len(data)
    value ^= value >> 16
    value = (value * 0x85EBCA6B) & mask
    value ^= value >> 13
    value = (value * 0xC2B2AE35) & mask
    value ^= value >> 16
    return value


# ---- the registry ---------------------------------------------------------------------------------------------

class Algorithm:
    """A name -> integer function with a width, a case fold and an encoding."""

    def __init__(self, name: str, bits: int, function, *, fold: str = "none", encoding: str = "utf-8",
                 builtin: bool = True, params: dict | None = None, spec: dict | None = None):
        if fold not in CASE_FOLDS or encoding not in ENCODINGS:
            raise HashError("bad_codec", "fold is %s and encoding is %s" % ("/".join(CASE_FOLDS), "/".join(ENCODINGS)))
        self.name, self.bits, self.function, self.fold, self.encoding = name, bits, function, fold, encoding
        self.builtin, self.params = builtin, dict(params or {})
        # `spec` is the algorithm as data (codec and its parameters); the Rust port hashes from it (see `native_spec`).
        self.spec = dict(spec) if spec else None
        self._fast = None
        module = trace_native.native()
        if module is not None and self.spec is not None:
            try:
                self._fast = module.HashFn(self.native_spec())
            except (module.TraceFallback, OverflowError):
                self._fast = None

    def native_spec(self) -> dict:
        """The full spec the Rust side builds an algorithm from."""
        return {**(self.spec or {}), "name": self.name, "bits": self.bits, "fold": self.fold, "encoding": self.encoding}

    def __call__(self, text: str | bytes) -> int:
        fast = self._fast
        if fast is not None and isinstance(text, (str, bytes)):
            module = trace_native.native()
            try:
                return fast.hash_text(text) if isinstance(text, str) else fast.hash_bytes(text)
            except module.TraceHashError as exc:
                raise HashError(*exc.args) from None
            except (module.TraceFallback, UnicodeEncodeError):
                pass     # the Python path below answers (or raises) exactly as before
        if isinstance(text, str):
            if self.fold == "lower":
                text = text.lower()
            elif self.fold == "upper":
                text = text.upper()
            text = text.encode(self.encoding)
        return self.function(text)

    def describe(self) -> dict:
        return {"name": self.name, "bits": self.bits, "fold": self.fold, "encoding": self.encoding,
                "builtin": self.builtin, "params": self.params}


def _builtins() -> dict[str, Algorithm]:
    table = {
        "fnv1a32": Algorithm("fnv1a32", 32, lambda data: fnv(data, 32), spec={"codec": "fnv", "variant": "1a", "width": 32}),
        "fnv1a64": Algorithm("fnv1a64", 64, lambda data: fnv(data, 64), spec={"codec": "fnv", "variant": "1a", "width": 64}),
        "fnv1_32": Algorithm("fnv1_32", 32, lambda data: fnv(data, 32, variant="1"),
                             spec={"codec": "fnv", "variant": "1", "width": 32}),
        "fnv1_64": Algorithm("fnv1_64", 64, lambda data: fnv(data, 64, variant="1"),
                             spec={"codec": "fnv", "variant": "1", "width": 64}),
        "crc32": Algorithm("crc32", 32, crc32, spec={"codec": "crc32"}),
        "murmur3_32": Algorithm("murmur3_32", 32, lambda data: murmur3_32(data, 0), params={"seed": 0},
                                spec={"codec": "murmur3", "seed": 0}),
    }
    return table


BUILTIN_VECTORS = {
    "fnv1a32": {"": 0x811C9DC5, "a": 0xE40C292C, "foobar": 0xBF9CF968},
    "fnv1a64": {"": 0xCBF29CE484222325, "a": 0xAF63DC4C8601EC8C, "foobar": 0x85944171F73967E8},
    "fnv1_32": {"": 0x811C9DC5, "a": 0x050C5D7E, "foobar": 0x31F0B262},
    "fnv1_64": {"": 0xCBF29CE484222325, "a": 0xAF63BD4C8601B7BE, "foobar": 0x340D8765A4DDA9C2},
    "crc32": {"": 0, "123456789": 0xCBF43926},
    "murmur3_32": {"": 0, "test": 0xBA6BD213, "Hello, world!": 0xC0363E43},
}


def parse_hash(text) -> int:
    """`0x...` / decimal text or an int to an unsigned integer."""
    if isinstance(text, bool):
        raise HashError("bad_hash", "a hash is a number")
    if isinstance(text, int):
        value = text
    else:
        try:
            value = int(str(text).strip(), 0)
        except ValueError:
            raise HashError("bad_hash", "%r is not a hash" % (text,)) from None
    if value < 0 or value >= 1 << 64:
        raise HashError("bad_hash", "a hash is an unsigned value of at most 64 bits")
    return value


def format_hash(value: int) -> str:
    return "0x%x" % value


class Registry:
    """Built-in algorithms plus the codecs a profile supplied (each proven by its vectors)."""

    def __init__(self):
        self.algorithms = _builtins()

    def names(self) -> list[str]:
        return sorted(self.algorithms)

    def get(self, name: str) -> Algorithm:
        try:
            return self.algorithms[name]
        except KeyError:
            raise HashError("unknown_algorithm", "no hash algorithm %r; known: %s" % (name, ", ".join(self.names()))) from None

    def compute(self, name: str, text: str | bytes) -> int:
        return self.get(name)(text)

    def add_codec(self, codec: dict) -> Algorithm:
        """Register a profile codec: {id, base, bits?, params, fold?, encoding?, vectors: [{input, output}]}.

        Vectors are mandatory and must all reproduce; the codec is registered only then. A profile cannot replace a
        built-in name."""
        name = codec.get("id")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", name):
            raise HashError("bad_codec", "codec id must be lowercase letters, digits, _ . -")
        if name in self.algorithms and self.algorithms[name].builtin:
            raise HashError("codec_shadows_builtin", "codec %s would replace a built-in algorithm" % name)
        vectors = codec.get("vectors")
        if not isinstance(vectors, list) or not vectors:
            raise HashError("vectors_required", "codec %s has no test vectors; a profile codec is refused without them" % name)
        params = dict(codec.get("params") or {})
        base, fold, encoding = codec.get("base"), codec.get("fold", "none"), codec.get("encoding", "utf-8")
        bits = codec.get("bits")
        if base in ("fnv1", "fnv1a"):
            width = int(bits or 32)
            basis = parse_hash(params["basis"]) if "basis" in params else None
            prime = parse_hash(params["prime"]) if "prime" in params else None
            function = lambda data, v=base[3:], w=width, b=basis, p=prime: fnv(data, w, variant=v, basis=b, prime=p)  # noqa: E731
            spec = {"codec": "fnv", "variant": base[3:], "width": width, "basis": basis, "prime": prime}
        elif base == "crc":
            width = int(bits or params.get("width", 32))
            crc_params = {"width": width}
            for key in ("poly", "init", "xorout"):
                if key in params:
                    crc_params[key] = parse_hash(params[key])
            for key in ("refin", "refout"):
                if key in params:
                    crc_params[key] = bool(params[key])
            function = lambda data, kw=crc_params: crc_generic(data, **kw)  # noqa: E731
            spec = {"codec": "crc", **crc_params}
        elif base == "murmur3_32":
            width = 32
            seed = parse_hash(params.get("seed", 0))
            function = lambda data, s=seed: murmur3_32(data, s)  # noqa: E731
            spec = {"codec": "murmur3", "seed": seed}
        else:
            raise HashError("bad_codec", "codec %s: base must be fnv1, fnv1a, crc or murmur3_32" % name)
        algorithm = Algorithm(name, width, function, fold=fold, encoding=encoding, builtin=False,
                              params={key: (format_hash(parse_hash(value)) if isinstance(value, (int, str)) and key in
                                            ("basis", "prime", "poly", "init", "xorout", "seed") else value)
                                      for key, value in params.items()}, spec=spec)
        for index, vector in enumerate(vectors):
            if not isinstance(vector, dict) or "input" not in vector or "output" not in vector:
                raise HashError("bad_vector", "codec %s vector %d needs input and output" % (name, index))
            expected = parse_hash(vector["output"])
            actual = algorithm(str(vector["input"]))
            if actual != expected:
                raise HashError("vector_mismatch", "codec %s vector %d: %r hashes to %s, the profile says %s"
                                % (name, index, vector["input"], format_hash(actual), format_hash(expected)))
        self.algorithms[name] = algorithm
        return algorithm


def verify_builtins() -> dict:
    """Run the built-in vectors; `ok` is false on the first algorithm that disagrees (a broken install, not a user error)."""
    registry = Registry()
    bad = [{"algorithm": name, "input": text, "expected": format_hash(expected),
            "actual": format_hash(registry.compute(name, text))}
           for name, vectors in BUILTIN_VECTORS.items() for text, expected in vectors.items()
           if registry.compute(name, text) != expected]
    return {"ok": not bad, "checked": sum(len(v) for v in BUILTIN_VECTORS.values()), "mismatches": bad}


# ---- the dictionary -------------------------------------------------------------------------------------------

class Dictionary:
    """Names with their sources. A hash that two different names produce is `ambiguous`; no name is chosen."""

    def __init__(self, registry: Registry | None = None, algorithms: list[str] | None = None):
        self.registry = registry or Registry()
        self.algorithms = list(algorithms or self.registry.names())
        self._sources: dict[str, set[str]] = {}
        self._index: dict[tuple[str, int], set[str]] = {}
        # With HYDRALYSIS_IMPL=rust the names, their sources and the index live in Rust (one copy of each name, numbers for
        # the index): `_native` is that store. A dictionary over an algorithm the port cannot hash stays in Python.
        self._native = self._native_store()

    def _native_store(self):
        module = trace_native.native()
        if module is None:
            return None
        try:
            distinct = list(dict.fromkeys(self.algorithms))
            specs = []
            for name in distinct:
                algorithm = self.registry.algorithms.get(name)
                if algorithm is None or algorithm.spec is None:
                    return None
                specs.append(algorithm.native_spec())
            return module.NativeDictionary(specs, [str(name) for name in self.algorithms])
        except (module.TraceFallback, TypeError, OverflowError):
            return None

    @property
    def sources(self) -> dict[str, set[str]]:
        """name -> the set of sources that gave it (a snapshot when the dictionary lives in Rust)."""
        if self._native is not None:
            return {name: set(sources) for name, sources in self._native.entries()}
        return self._sources

    def __len__(self) -> int:
        return len(self._native) if self._native is not None else len(self._sources)

    def _native_add(self, call, *args):
        module = trace_native.native()
        try:
            return call(*args)
        except module.TraceHashError as exc:
            raise HashError(*exc.args) from None
        except module.TraceFallback:
            for value in args:        # a lone surrogate: Python's encode raises the error it always did
                if isinstance(value, str):
                    value.encode("utf-8")
            raise

    def add(self, name: str, source: str) -> None:
        if self._native is not None:
            if not isinstance(name, str):
                raise HashError("bad_name", "a dictionary name is 1..%d characters without NUL" % MAX_NAME)
            if not isinstance(source, str):
                raise HashError("source_required", "every dictionary entry records its source")
            self._native_add(self._native.add, name, source)
            return
        if not isinstance(name, str) or not name or len(name) > MAX_NAME or "\0" in name:
            raise HashError("bad_name", "a dictionary name is 1..%d characters without NUL" % MAX_NAME)
        if not isinstance(source, str) or not source.strip():
            raise HashError("source_required", "every dictionary entry records its source")
        if name not in self.sources:
            if len(self.sources) >= MAX_ENTRIES:
                raise HashError("dictionary_full", "the dictionary holds at most %d names" % MAX_ENTRIES)
            for algorithm in self.algorithms:
                self._index.setdefault((algorithm, self.registry.compute(algorithm, name)), set()).add(name)
        self._sources.setdefault(name, set()).add(source)

    def _add_all(self, names: list[str], source: str) -> int:
        """Add NAMES one after the other under SOURCE (the Rust store takes them in one call)."""
        if self._native is not None and all(isinstance(name, str) for name in names) and isinstance(source, str):
            return self._native_add(self._native.add_many, names, source)
        for name in names:
            self.add(name, source)
        return len(names)

    def add_lines(self, text: str, source: str) -> int:
        if self._native is not None:
            lines = [line.strip() for line in text.splitlines()]
            return self._add_all([line for line in lines if line and not line.startswith("#")], source)
        count = 0
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                self.add(line, source)
                count += 1
        return count

    def add_manifest(self, paths: list[str], source: str) -> int:
        """File or archive manifest: each path contributes its full text, its base name and its stem."""
        count = 0
        for path in paths:
            normal = str(path).replace("\\", "/")
            base = normal.rsplit("/", 1)[-1]
            names = [name for name in {normal, base, base.rsplit(".", 1)[0]} if name]
            self._add_all(names, source)
            count += len(names)
        return count

    def add_corpus(self, path: Path, source: str | None = None) -> int:
        """Names from a type corpus (docs/type-corpus.md): type, field, enum member, function and class names."""
        label = source or "type corpus %s" % Path(path).name
        count = 0
        for number, line in enumerate(Path(path).read_text("utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except ValueError as exc:
                raise HashError("corpus_invalid", "%s line %d is not JSON: %s" % (path, number, exc)) from exc
            names = corpus_names(record)
            self._add_all(names, "%s line %d" % (label, number))
            count += len(names)
        return count

    def resolve(self, algorithm: str, value) -> dict:
        """{status: resolved|ambiguous|unknown, names: [{name, sources}]} for one hash under one algorithm."""
        if algorithm not in self.algorithms:
            raise HashError("unknown_algorithm", "algorithm %s is not in this dictionary" % algorithm)
        number = parse_hash(value)
        if self._native is not None:
            return self._native.resolve(algorithm, number)
        names = sorted(self._index.get((algorithm, number), ()))
        status = "unknown" if not names else "resolved" if len(names) == 1 else "ambiguous"
        return {"algorithm": algorithm, "hash": format_hash(number), "status": status,
                "names": [{"name": name, "sources": sorted(self._sources[name])} for name in names]}

    def collisions(self) -> list[dict]:
        if self._native is not None:
            return self._native.collisions()
        found = [self.resolve(algorithm, value) for (algorithm, value), names in sorted(self._index.items()) if len(names) > 1]
        return found

    def digest(self) -> str:
        """Identifies this dictionary content (names, sources, algorithms) for an interpretation revision."""
        if self._native is not None:
            return self._native.digest()
        payload = {"algorithms": sorted(self.algorithms),
                   "entries": [[name, sorted(self._sources[name])] for name in sorted(self._sources)]}
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def corpus_names(record: dict) -> list[str]:
    names = []
    for key in ("name", "class"):
        if isinstance(record.get(key), str):
            names.append(record[key])
    for field in record.get("fields") or ():
        if isinstance(field, dict) and isinstance(field.get("name"), str):
            names.append(field["name"])
    for member in record.get("members") or ():
        if isinstance(member, (list, tuple)) and member and isinstance(member[0], str):
            names.append(member[0])
    for name in record.get("names") or ():
        if isinstance(name, str):
            names.append(name)
    return [name for name in names if name]


# ---- static use -----------------------------------------------------------------------------------------------

def annotate_constants(dictionary: Dictionary, constants: list[dict], algorithms: list[str] | None = None) -> list[dict]:
    """For each {value, where?}, the dictionary's answer under every algorithm of the same width or the named ones.

    A constant that resolves under two algorithms to different names, or to two names under one, is `ambiguous`."""
    if dictionary._native is not None and constants:
        names = list(algorithms or dictionary.algorithms)
        try:
            declared = [(name, dictionary.registry.get(name).bits) for name in names]
            numbers = [parse_hash(constant["value"]) for constant in constants]
        except (HashError, KeyError, TypeError):
            declared = None      # the loop below raises exactly what it always did
        if declared is not None and all(name in dictionary.algorithms for name in names):
            module = trace_native.native()
            try:
                notes = dictionary._native.annotate(numbers, declared)
            except module.TraceFallback:
                notes = None
            if notes is not None:
                return [{"value": format_hash(number), "where": constant.get("where"), "status": status, "answers": answers}
                        for number, constant, (status, answers) in zip(numbers, constants, notes)]
    out = []
    for constant in constants:
        number = parse_hash(constant["value"])
        found = []
        for algorithm in algorithms or dictionary.algorithms:
            bits = dictionary.registry.get(algorithm).bits
            if number >= 1 << bits:
                continue
            answer = dictionary.resolve(algorithm, number)
            if answer["status"] != "unknown":
                found.append(answer)
        names = {item["name"] for answer in found for item in answer["names"]}
        status = "unknown" if not names else "resolved" if len(names) == 1 and all(a["status"] == "resolved" for a in found) \
            else "ambiguous"
        out.append({"value": format_hash(number), "where": constant.get("where"), "status": status, "answers": found})
    return out


def interpretation(dictionary: Dictionary, algorithm: str, values: list, *, parent: str | None = None) -> dict:
    """A trace interpretation revision (14.5) naming hashed ids. Raw values are kept; nothing is rewritten.

    The revision id is derived from the dictionary content, the algorithm and the values, so the same inputs give the
    same revision and a changed dictionary gives a new one."""
    if dictionary._native is not None and algorithm in dictionary.algorithms:
        try:
            numbers = [parse_hash(value) for value in values]
            header, rows = dictionary._native.interpret(algorithm, numbers, parent)
        except (trace_native.native().TraceFallback, HashError, TypeError):
            pass          # the Python lines below raise exactly what they always did
        else:
            counts = header.pop("counts")
            return {**header, "rows": rows, "counts": counts}
    rows = [dictionary.resolve(algorithm, value) for value in values]
    revision = hashlib.sha256(json.dumps({"dictionary": dictionary.digest(), "algorithm": algorithm,
                                          "values": [row["hash"] for row in rows]}, sort_keys=True,
                                         separators=(",", ":")).encode("utf-8")).hexdigest()
    return {"kind": "hash-names/1", "revision": "hn_" + revision[:32], "parent": parent, "algorithm": algorithm,
            "dictionary_sha256": dictionary.digest(), "raw_preserved": True, "rows": rows,
            "counts": {status: sum(row["status"] == status for row in rows) for status in ("resolved", "ambiguous", "unknown")}}


def interpret_events(dictionary: Dictionary, algorithm: str, events: list[dict], fields: list[str]) -> dict:
    """Resolve the hashed payload FIELDS of EVENTS (dicts with event_id and payload). Returns the revision plus
    per-event annotations; the events themselves are not changed."""
    if dictionary._native is not None and algorithm in dictionary.algorithms and isinstance(events, list) \
            and isinstance(fields, list) and all(isinstance(field, str) for field in fields):
        try:
            header, annotations = dictionary._native.interpret_events(algorithm, events, fields)
        except trace_native.native().TraceFallback:
            pass
        else:
            return {"interpretation": header, "annotations": annotations}
    wanted = []
    notes = []
    for event in events:
        payload = event.get("payload") or {}
        for field in fields:
            if field in payload and not isinstance(payload[field], (dict, list)):
                try:
                    number = parse_hash(payload[field])
                except HashError:
                    continue
                wanted.append(number)
                notes.append((event.get("event_id"), field, number))
    revision = interpretation(dictionary, algorithm, sorted(set(wanted)))
    by_hash = {row["hash"]: row for row in revision["rows"]}
    return {"interpretation": {key: value for key, value in revision.items() if key != "rows"},
            "annotations": [{"event_id": event_id, "field": field, "raw": format_hash(number),
                             **{k: by_hash[format_hash(number)][k] for k in ("status", "names")}}
                            for event_id, field, number in notes]}


def constant_forms(value: int, bits: int) -> list[bytes]:
    """The little-endian byte forms of a hash constant: as an immediate or data of its own width."""
    size = bits // 8
    return [value.to_bytes(size, "little")]


def scan_constants(image, hashes: list[tuple[int, int]], *, limit: int = 50, functions: list[tuple[int, int]] | None = None) -> list[dict]:
    """Where an image carries the constants. HASHES is [(value, bits)]. Searches every section's file bytes.

    Each hit says the section, the RVA, whether the section is executable (an immediate in code) and, when the image
    can say (x64 pdata, or FUNCTIONS: analysed [start, end) RVA ranges for leaf functions without unwind data), the containing function. Hits are bounded by LIMIT and `truncated` says so."""
    routed = _routed("scan_constants")
    if routed is not None and isinstance(image.data, bytes) and isinstance(limit, int) and not isinstance(limit, bool) \
            and limit >= 0 and (functions is None or all(len(pair) == 2 for pair in functions)):
        try:
            sections = [(bytes(section.Name), section.VirtualAddress, section.PointerToRawData, section.SizeOfRawData,
                         section.Characteristics) for section in image.sections]
            bounds = getattr(image, "_bounds", None)
            hits, _truncated = routed(image.data, sections, [(value, bits) for value, bits in hashes], limit, bounds,
                                      [tuple(pair) for pair in functions] if functions else None)
            return hits
        except (trace_native.native().TraceFallback, AttributeError, TypeError, OverflowError):
            pass
    hits: list[dict] = []
    truncated = False
    for section in image.sections:
        name = section.Name.rstrip(b"\0").decode("utf-8", "replace")
        raw = image.data[section.PointerToRawData: section.PointerToRawData + section.SizeOfRawData]
        executable = bool(section.Characteristics & 0x20000000)
        for value, bits in hashes:
            for form in constant_forms(value, bits):
                start = 0
                while True:
                    found = raw.find(form, start)
                    if found < 0:
                        break
                    start = found + 1
                    if len(hits) >= limit:
                        truncated = True
                        break
                    rva = section.VirtualAddress + found
                    hit = {"value": format_hash(value), "bits": bits, "rva": "rva:%#x" % rva, "section": name,
                           "context": "code-immediate" if executable else "data"}
                    bounds = None
                    try:
                        bounds = image._bounds(rva) if executable else None
                    except Exception:  # noqa: BLE001 - an image without pdata simply has no function to name
                        bounds = None
                    if bounds is None and executable and functions:
                        bounds = next(((a, b) for a, b in functions if a <= rva < b), None)
                    if bounds:
                        hit["function"] = "rva:%#x" % bounds[0]
                    hits.append(hit)
                if truncated:
                    break
            if truncated:
                break
        if truncated:
            break
    return sorted(hits, key=lambda hit: (int(hit["rva"][4:], 16), hit["value"])) if not truncated else hits


def find_name_users(dictionary: Dictionary, name: str, image, *, algorithms: list[str] | None = None, limit: int = 50,
                    functions: list[tuple[int, int]] | None = None) -> dict:
    """A search for NAME: its hash under each algorithm, and the code or data in IMAGE that carries each hash.

    A hash that the dictionary also gives to another name is flagged `ambiguous`: a hit is then a candidate, not proof."""
    wanted = []
    per_algorithm = []
    for algorithm in algorithms or dictionary.algorithms:
        engine = dictionary.registry.get(algorithm)
        value = engine(name)
        answer = dictionary.resolve(algorithm, value)
        per_algorithm.append({"algorithm": algorithm, "hash": format_hash(value),
                              "status": "ambiguous" if answer["status"] == "ambiguous" else
                              ("resolved" if answer["status"] == "resolved" else "unknown")})
        wanted.append((value, engine.bits))
    seen, unique = set(), []
    for pair in wanted:
        if pair not in seen:
            seen.add(pair)
            unique.append(pair)
    hits = scan_constants(image, unique, limit=limit, functions=functions)
    return {"name": name, "algorithms": per_algorithm, "hits": hits, "truncated": len(hits) >= limit}
