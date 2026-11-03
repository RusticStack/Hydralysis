"""Rust implementation of the evidence ledger and bundles behind HYDRALYSIS_IMPL=rust.

`evidence.py` and `evidence_bundle.py` call `install_evidence` / `install_bundle` at import time when the environment
variable is `rust`; their public functions are replaced by thin wrappers over the single `hydralysis_rs.evidence_call`
dispatcher (rust/crates/hy-py/src/evidence.rs, over hy-store's evidence.rs and bundle.rs). Functions that take a sqlite
connection or a sqlite row (`connect`, `_insert`, `_select`, `decode_row`, `verify_row`, `content_of_row`) stay Python.
"""

from __future__ import annotations

import json
import os

from hydralysis import _rust_store  # noqa: F401  (puts HYDRALYSIS_RS_DIR on sys.path before the import below)

try:
    import hydralysis_rs as rs
except ImportError as exc:  # pragma: no cover
    raise ImportError("HYDRALYSIS_IMPL=rust needs the hydralysis_rs extension: %s" % exc) from exc


def _call(op: str, **args):
    encoded = json.dumps(args)
    try:
        return json.loads(rs.evidence_call(op, encoded))
    except ValueError as exc:
        # A lone surrogate survives json.dumps as an escape that the Rust parser (UTF-8 only) refuses.
        if "hex escape" in str(exc) or "surrogate" in str(exc):
            raise ValueError("canonical form refuses an unpaired surrogate: %s" % exc) from exc
        raise


def _p(value):
    return None if value is None else os.fspath(value)


def install_evidence(ev) -> None:
    def simple(op, key="value"):
        def wrapper(value):
            return _call(op, **{key: value})
        wrapper.__name__ = op
        return wrapper

    def normalize_coverage(value=None):
        return _call("normalize_coverage", value=value)

    def merge_limitations(coverage, limitations=()):
        return _call("merge_limitations", coverage=coverage, limitations=list(limitations))

    def build_content(**fields):
        fields["limitations"] = list(fields.get("limitations") or ())
        fields["evidence_links"] = sorted({str(link) for link in fields.get("evidence_links") or ()})
        return _call("build_content", **fields)

    def verify_content(content, evidence_id):
        return _call("verify_content", content=content, evidence_id=evidence_id)

    def check_content(content, evidence_id):
        return _call("check_content", content=content, evidence_id=evidence_id)

    def add_claim(path, **fields):
        fields["limitations"] = list(fields.get("limitations") or ())
        who = ev._who()
        return _call("add_claim", path=_p(path), who=list(who), now=ev._now(), **fields)

    def query(path, game="", subsystem="", address="", build="", include_superseded=False, limit=50, verify=True,
              evidence_id=""):
        return _call("query", path=_p(path), game=game, subsystem=subsystem, address=address, build=build,
                     include_superseded=include_superseded, limit=limit, verify=verify, evidence_id=evidence_id)

    def get_claim(path, evidence_id):
        return _call("get_claim", path=_p(path), evidence_id=evidence_id)

    def verify_ledger(path):
        return _call("verify_ledger", path=_p(path))

    def records_for_bundle(path, game="", subsystem="", build=""):
        return _call("records_for_bundle", path=_p(path), game=game, subsystem=subsystem, build=build)

    def import_records(path, records):
        return _call("import_records", path=_p(path), records=records, who=list(ev._who()), now=ev._now())

    def list_claims(path, game="", limit=50, **filters):
        return _call("list_claims", path=_p(path), game=game, limit=limit, **filters)

    def export(path, out, game="", subsystem=""):
        return _call("export", path=_p(path), out=_p(out), game=game, subsystem=subsystem)

    ev.canonical_json = simple("canonical_json")
    ev.canonical_digest = simple("canonical_digest")
    ev.compute_evidence_id = simple("compute_evidence_id")
    ev.check_limitation_code = simple("check_limitation_code")
    ev.derived_limitations = simple("derived_limitations", "value")
    ev.check_from_trace = simple("check_from_trace")
    ev.check_meta = simple("check_meta")
    for function in (normalize_coverage, merge_limitations, build_content, verify_content, check_content, add_claim, query,
                     get_claim, verify_ledger, records_for_bundle, import_records, list_claims, export):
        setattr(ev, function.__name__, function)
    ev.IMPL = "rust"


def install_bundle(bundle) -> None:
    from pathlib import Path

    def guard_payload(value, where="value"):
        return _call("guard_payload", value=value, where=where)

    def check_pin(pin, session):
        return _call("check_pin", pin=pin, session=session)

    def stub_pin(session, revision):
        return _call("stub_pin", session=session, revision=revision)

    def export_bundle(db_path, out, *, game="", subsystem="", build="", captures_dir=None, overwrite=False, traces_dir=None):
        return _call("export_bundle", db_path=_p(db_path), out=_p(out), game=game, subsystem=subsystem, build=build,
                     captures_dir=_p(captures_dir), traces_dir=_p(traces_dir), overwrite=overwrite,
                     who=list(bundle.evidence._who()), now=bundle.evidence._now())

    def load_bundle(folder):
        loaded = _call("load_bundle", folder=_p(folder))
        loaded["capture_blobs"] = {key: bytes.fromhex(value) for key, value in loaded["capture_blobs"].items()}
        return loaded

    def verify_bundle(folder):
        return _call("verify_bundle", folder=_p(folder))

    def compare_bundles(left, right):
        return _call("compare_bundles", left=_p(left), right=_p(right))

    def import_bundle(folder, db_path):
        return _call("import_bundle", folder=_p(folder), db_path=_p(db_path), who=list(bundle.evidence._who()),
                     now=bundle.evidence._now())

    def handle(capability, request):
        from hydralysis.config import evidence_path
        options = request.get("options") or {}
        args = request.get("args") or {}
        resolved = evidence_path(str(options.get("db") or args.get("db") or ""))
        return _call("handle", request=request, resolved_db=_p(resolved), who=list(bundle.evidence._who()),
                     now=bundle.evidence._now())

    for function in (guard_payload, check_pin, stub_pin, export_bundle, load_bundle, verify_bundle, compare_bundles,
                     import_bundle, handle):
        setattr(bundle, function.__name__, function)
    bundle.IMPL = "rust"
    assert Path
