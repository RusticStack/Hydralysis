"""Bump the Hydra Engine pin of this tree to a release, from the release's own files.

    python tools/bump_hydra.py --release 12.3-hydra.4 --dist <folder with the release files>            # shows the edits
    python tools/bump_hydra.py --release 12.3-hydra.4 --dist <folder> --write                           # applies them
    python tools/bump_hydra.py --release 12.3-hydra.4 --dist <folder> --check                           # exit 1 if anything would change
    python tools/bump_hydra.py ... --site-root <site checkout>                             # the site's constants too

PROTOCOL-3.md, section 5 (R1 owns this script, Y4a runs it, S2 owns the site edit it makes). Nothing here tags,
pushes or publishes: it reads two archives that already exist and edits text files.

What it reads (the engine and the client zip of the release; ``--dist`` finds ``hydra-engine-<release>-win_x86_64.zip``
and ``hydra-client-<release>.zip`` in a folder and cross-checks ``SHA256SUMS`` when the folder has one):

* the SHA-256 and size of each archive;
* the client's own stamps (``HYDRA_RELEASE``, ``CLIENT_VERSION``, ``PROTOCOL`` in ``ghidra_session.py``): the release
  stamp must equal ``--release``, and the other two become the pin;
* the engine's ``hydra.properties`` inside ``HeadlessSession.jar``: ``hydra.version`` must equal ``--release``. An
  engine built without the stamp says ``<Ghidra version>-hydra.dev`` to Hydralysis, which classifies it as stock, so a
  zip that lacks the stamp is refused here, before a pin points at it.

What it writes, and nothing else (``EDIT_SET``; ``tests/test_bump_hydra.py`` asserts it):

* ``src/hydralysis/hydra.py``: ``RELEASE``, ``PROTOCOL``, ``CLIENT_VERSION`` and ``ASSETS`` (SHA-256 and size);
* ``tests/fakehydra.py``: the release (``hydraVersion``) of the fake daemon's ``hello``; its base protocol stays 2, a protocol 3
  engine is modelled through ``hello_extra``;
* ``README.md`` (the ``backend install`` paragraph) and ``THIRD_PARTY.md`` (the engine row):
  the one pin sentence of each.

With ``--site-root`` it also writes the site's release constant (``src/lib/site.ts``, and a ``protocol`` constant there
when one exists) and the pinned literals of ``installation.ts``, ``clients.ts`` and ``mcp-server.ts``
(``SITE_EDIT_SET``). The site's ``changelog.tsx`` and the prose example in ``installation.ts`` are history and
stay as they are.

Historical, never edited: ``docs/golden-harness.md``, ``docs/verification-fixtures.md`` (dated reports).

Every edit is an anchored replacement that must match exactly the expected number of times; a file whose anchor is
missing or ambiguous stops the run before anything is written (all edits are computed first, then written).
Standard library only.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import io
import json
import os
import re
import sys
import zipfile
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent

RELEASE_RE = re.compile(r"^\d+\.\d+-hydra\.\d+$")
LITERAL = r"\d+\.\d+-hydra\.\d+"

HYDRA_PY = "src/hydralysis/hydra.py"
FAKE = "tests/fakehydra.py"
README = "README.md"
THIRD_PARTY = "THIRD_PARTY.md"
#: The files this script may write in the Hydralysis tree. Anything else is a bug (the test asserts it).
EDIT_SET = (HYDRA_PY, FAKE, README, THIRD_PARTY)

SITE_SITE = "src/lib/site.ts"
SITE_INSTALL = "src/docs/pages/installation.ts"
SITE_CLIENTS = "src/docs/pages/clients.ts"
SITE_MCP = "src/docs/pages/mcp-server.ts"
#: The files this script may write in the site repository (--site-root).
SITE_EDIT_SET = (SITE_SITE, SITE_INSTALL, SITE_CLIENTS, SITE_MCP)

HISTORICAL = ("docs/golden-harness.md", "docs/verification-fixtures.md")

ENGINE_ASSET = "hydra-engine-{release}-win_x86_64.zip"
CLIENT_ASSET = "hydra-client-{release}.zip"
JAR_SUFFIX = "Features/HeadlessSession/lib/HeadlessSession.jar"


class BumpError(Exception):
    """A refusal: nothing has been written."""


def sha256_of(path: Path) -> tuple[str, int]:
    digest, size = hashlib.sha256(), 0
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def read_client_stamps(client_zip: Path) -> dict[str, str]:
    """HYDRA_RELEASE, CLIENT_VERSION and PROTOCOL of the ghidra_session.py inside the client zip."""
    with zipfile.ZipFile(client_zip) as archive:
        names = [n for n in archive.namelist() if n.endswith("/ghidra_session.py") or n == "ghidra_session.py"]
        if len(names) != 1:
            raise BumpError("%s: expected one ghidra_session.py, found %d" % (client_zip, len(names)))
        text = archive.read(names[0]).decode("utf-8", "replace")
    stamps = {}
    for name in ("HYDRA_RELEASE", "CLIENT_VERSION", "PROTOCOL"):
        match = re.search(r'^%s\s*=\s*"?([^"\n]+?)"?\s*$' % name, text, re.M)
        if not match:
            raise BumpError("%s: ghidra_session.py has no %s line" % (client_zip, name))
        stamps[name] = match.group(1)
    return stamps


def read_engine_version(engine_zip: Path) -> str | None:
    """hydra.version from hydra.properties inside HeadlessSession.jar inside the engine zip; None when absent/empty."""
    with zipfile.ZipFile(engine_zip) as archive:
        jars = [n for n in archive.namelist() if n.endswith(JAR_SUFFIX)]
        if len(jars) != 1:
            raise BumpError("%s: expected one %s, found %d" % (engine_zip, JAR_SUFFIX, len(jars)))
        with zipfile.ZipFile(io.BytesIO(archive.read(jars[0]))) as jar:
            try:
                text = jar.read("hydra.properties").decode("utf-8", "replace")
            except KeyError:
                return None
    match = re.search(r"^hydra\.version=(\S*)", text, re.M)
    return match.group(1) if match and match.group(1) else None


def parse_sums(path: Path) -> dict[str, str]:
    sums = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            sums[parts[1].strip().lstrip("*")] = parts[0].lower()
    return sums


def gather(release: str, engine_zip: Path, client_zip: Path, sums: Path | None, allow_unstamped: bool) -> dict:
    """Everything the edits need, with the checks that refuse a wrong archive."""
    if not RELEASE_RE.match(release):
        raise BumpError("release %r is not <ghidra version>-hydra.<n> (for example 12.3-hydra.4)" % release)
    for path in (engine_zip, client_zip):
        if not path.is_file():
            raise BumpError("missing archive: %s" % path)
    stamps = read_client_stamps(client_zip)
    if stamps["HYDRA_RELEASE"] != release:
        raise BumpError("the client zip is stamped HYDRA_RELEASE=%s, not %s" % (stamps["HYDRA_RELEASE"], release))
    if not re.fullmatch(r"\d+", stamps["PROTOCOL"]) or not re.fullmatch(r"\d+\.\d+\.\d+", stamps["CLIENT_VERSION"]):
        raise BumpError("the client zip stamps are malformed: %r" % stamps)
    engine_stamp = read_engine_version(engine_zip)
    if engine_stamp != release and not allow_unstamped:
        raise BumpError("the engine zip's hydra.properties says hydra.version=%s, not %s: Hydralysis would classify "
                        "this engine as stock (the release workflow stamps it; see CHANGELOG/README of the engine)"
                        % (engine_stamp or "(empty)", release))
    assets = {}
    for key, path in (("engine", engine_zip), ("client", client_zip)):
        digest, size = sha256_of(path)
        assets[key] = {"name": path.name, "sha256": digest, "size": size}
    if sums is not None:
        listed = parse_sums(sums)
        for info in assets.values():
            want = listed.get(info["name"])
            if want is None:
                raise BumpError("%s does not list %s" % (sums, info["name"]))
            if want != info["sha256"]:
                raise BumpError("%s lists %s for %s but the file hashes to %s" % (sums, want, info["name"], info["sha256"]))
    return {"release": release, "protocol": int(stamps["PROTOCOL"]), "client_version": stamps["CLIENT_VERSION"],
            "assets": assets, "engine_stamp": engine_stamp}


def replace_exact(text: str, pattern: str, repl, count: int, what: str, flags: int = re.M) -> str:
    """Replace ``pattern`` and require exactly ``count`` matches (an anchor that moved stops the run)."""
    found = len(re.findall(pattern, text, flags))
    if found != count:
        raise BumpError("%s: expected %d match(es) of %s, found %d" % (what, count, pattern, found))
    return re.sub(pattern, repl, text, flags=flags)


def edit_hydra_py(text: str, info: dict, observed: str) -> str:
    what = HYDRA_PY
    release = info["release"]
    text = replace_exact(text, r'^RELEASE = "%s"(?=\r?$)' % LITERAL, 'RELEASE = "%s"' % release, 1, what)
    text = replace_exact(text, r"^PROTOCOL = \d+(?=\r?$)", "PROTOCOL = %d" % info["protocol"], 1, what)
    text = replace_exact(text, r'^CLIENT_VERSION = "\d+\.\d+\.\d+"(?=\r?$)', 'CLIENT_VERSION = "%s"' % info["client_version"], 1, what)
    def make_block(date: str) -> str:
        block = (
            "# SHA256SUMS of the release, observed %s and checked after download.\n"
            "ASSETS = {\n"
            '    "engine": {"url": _BASE + "hydra-engine-" + RELEASE + "-win_x86_64.zip",\n'
            '               "sha256": "%s", "size": %d},\n'
            '    "client": {"url": _BASE + "hydra-client-" + RELEASE + ".zip",\n'
            '               "sha256": "%s", "size": %d},\n'
            "}\n") % (date, info["assets"]["engine"]["sha256"], info["assets"]["engine"]["size"],
                      info["assets"]["client"]["sha256"], info["assets"]["client"]["size"])
        return block.replace("\n", "\r\n") if "\r\n" in text else block

    # Same hashes as the file already has: keep its date, so --check gives the same answer on every day.
    seen = re.search(r"^# SHA256SUMS of the release, observed ([^\r\n]*?) and checked after download\.", text, re.M)
    if seen and make_block(seen.group(1)) in text:
        return text
    block = make_block(observed)
    pattern = r"^# SHA256SUMS of the release, observed [^\n]*\n(?:ASSETS = \{\r?\n.*?^\}\r?\n)"
    return replace_exact(text, pattern, lambda _m: block, 1, what, re.M | re.S)


def edit_fake(text: str, info: dict) -> str:
    what = FAKE
    text = replace_exact(text, r'("hydraVersion": ")%s(")' % LITERAL, lambda m: m.group(1) + info["release"] + m.group(2), 1, what)
    # The base hello stays protocol 2: a protocol 3 engine is modelled through hello_extra (tests/fakehydra.py).
    return text


def edit_readme(text: str, info: dict) -> str:
    return replace_exact(text, r"(installs the pinned Hydra release \(\*\*)%s(\*\*)" % LITERAL,
                         lambda m: m.group(1) + info["release"] + m.group(2), 1, README)


def edit_third_party(text: str, info: dict) -> str:
    return replace_exact(text, r"(the pinned headless release \()%s(\))" % LITERAL,
                         lambda m: m.group(1) + info["release"] + m.group(2), 1, THIRD_PARTY)


def edit_site_site(text: str, info: dict) -> str:
    text = replace_exact(text, r'(^\s*release: ")%s(",)' % LITERAL, lambda m: m.group(1) + info["release"] + m.group(2), 1, SITE_SITE)
    # A protocol constant is S2's to add; when it is there the script keeps it equal to the pin.
    if re.search(r"^\s*protocol: \d+,", text, re.M):
        text = replace_exact(text, r"(^\s*protocol: )\d+(,)", lambda m: m.group(1) + str(info["protocol"]) + m.group(2), 1, SITE_SITE)
    return text


def edit_site_install(text: str, info: dict) -> str:
    # the two commands that name the zip; the sentence that explains the naming scheme is an example, not a pin
    return replace_exact(text, r"(hydra-engine-)%s(-win_x86_64\.zip)" % LITERAL,
                         lambda m: m.group(1) + info["release"] + m.group(2), 2, SITE_INSTALL)


def edit_site_clients(text: str, info: dict) -> str:
    return replace_exact(text, r'("hydraVersion": ")%s(")' % LITERAL, lambda m: m.group(1) + info["release"] + m.group(2), 1, SITE_CLIENTS)


def edit_site_mcp(text: str, info: dict) -> str:
    return replace_exact(text, r"(release \()%s(: the engine and its client\))" % LITERAL,
                         lambda m: m.group(1) + info["release"] + m.group(2), 1, SITE_MCP)


def read_text(path: Path) -> str:
    # newline="" keeps CRLF files CRLF: nothing is translated on the way in or out
    with open(path, "r", encoding="utf-8", newline="") as handle:
        return handle.read()


def plan(root: Path, info: dict, observed: str, site_root: Path | None) -> dict[Path, str]:
    """Compute every new text first; nothing is written here. Only files whose text changes are returned."""
    jobs = [(root, HYDRA_PY, lambda t: edit_hydra_py(t, info, observed)), (root, FAKE, lambda t: edit_fake(t, info)),
            (root, README, lambda t: edit_readme(t, info)), (root, THIRD_PARTY, lambda t: edit_third_party(t, info))]
    if site_root is not None:
        jobs += [(site_root, SITE_SITE, lambda t: edit_site_site(t, info)), (site_root, SITE_INSTALL, lambda t: edit_site_install(t, info)),
                 (site_root, SITE_CLIENTS, lambda t: edit_site_clients(t, info)), (site_root, SITE_MCP, lambda t: edit_site_mcp(t, info))]
    changes: dict[Path, str] = {}
    for base, rel, edit in jobs:
        path = base / rel
        if not path.is_file():
            raise BumpError("missing file: %s" % path)
        old = read_text(path)
        new = edit(old)
        if new != old:
            changes[path] = new
    return changes


def write_all(changes: dict[Path, str]) -> None:
    """Write every temp file first, then swap them in.

    Not atomic across files: a crash between two swaps leaves some files changed. A failing swap
    is rolled back (the files already swapped get their old bytes back) and leftover temps are
    removed on any failure.
    """
    temps: list[tuple[Path, Path]] = []
    done: list[tuple[Path, bytes | None]] = []
    try:
        for path, text in changes.items():
            temp = path.with_name(path.name + ".bump-tmp")
            temps.append((temp, path))
            with open(temp, "w", encoding="utf-8", newline="") as handle:
                handle.write(text)
        while temps:
            temp, path = temps[0]
            before = path.read_bytes() if path.exists() else None
            os.replace(temp, path)
            temps.pop(0)
            done.append((path, before))
    except BaseException:
        for path, before in reversed(done):
            try:
                if before is None:
                    path.unlink()
                else:
                    path.write_bytes(before)
            except OSError:
                pass
        raise
    finally:
        for temp, _ in temps:
            try:
                temp.unlink()
            except OSError:
                pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--release", required=True, help="for example 12.3-hydra.4")
    parser.add_argument("--dist", type=Path, help="folder with the release files (and SHA256SUMS, cross-checked when present)")
    parser.add_argument("--engine-zip", type=Path)
    parser.add_argument("--client-zip", type=Path)
    parser.add_argument("--sums", type=Path, help="a SHA256SUMS file to cross-check (default: <dist>/SHA256SUMS)")
    parser.add_argument("--root", type=Path, default=REPOSITORY, help="the Hydralysis tree (default: this one)")
    parser.add_argument("--site-root", type=Path, help="the site repository: also edit its release constants")
    parser.add_argument("--observed", default=None, help="date written in the ASSETS comment (default: today)")
    parser.add_argument("--allow-unstamped-engine", action="store_true",
                        help="pin an engine zip whose hydra.properties is empty (it will be treated as stock; for experiments)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="apply the edits (default: show them)")
    mode.add_argument("--check", action="store_true", help="exit 1 when any edit would change a file")
    args = parser.parse_args(argv)
    try:
        engine_zip, client_zip, sums = args.engine_zip, args.client_zip, args.sums
        if args.dist is not None:
            engine_zip = engine_zip or args.dist / ENGINE_ASSET.format(release=args.release)
            client_zip = client_zip or args.dist / CLIENT_ASSET.format(release=args.release)
            if sums is None and (args.dist / "SHA256SUMS").is_file():
                sums = args.dist / "SHA256SUMS"
        if engine_zip is None or client_zip is None:
            raise BumpError("give --dist, or both --engine-zip and --client-zip")
        info = gather(args.release, engine_zip, client_zip, sums, args.allow_unstamped_engine)
        observed = args.observed or datetime.date.today().isoformat()
        changes = plan(args.root, info, observed, args.site_root)
        # The edit set is a promise: refuse to write anything that is not in it.
        allowed = {(args.root / r).resolve() for r in EDIT_SET}
        if args.site_root is not None:
            allowed |= {(args.site_root / r).resolve() for r in SITE_EDIT_SET}
        stray = [p for p in changes if p.resolve() not in allowed]
        if stray:
            raise BumpError("internal error, edits outside the edit set: %s" % stray)
        if args.write:
            write_all(changes)
    except BumpError as exc:
        print("bump_hydra: refused, nothing written: %s" % exc, file=sys.stderr)
        return 2
    report = {"release": info["release"], "protocol": info["protocol"], "clientVersion": info["client_version"],
              "assets": info["assets"], "engineStamp": info["engine_stamp"], "written": bool(args.write),
              "changed": sorted(str(p) for p in changes)}
    print(json.dumps(report, indent=2))
    if args.check and changes:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
