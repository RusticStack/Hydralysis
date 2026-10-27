"""Who may cancel a durable job: the client that started it.

Starting a job returns an owner token; the job record keeps only its hash, with the
starting client and harness. Every client can list and read any job, but cancelling one
needs its token (a process remembers the tokens of the jobs it started, so an MCP session
can cancel its own jobs without passing one). A client whose identical request was
deduplicated onto an existing job gets that job, not its token.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

_TOKENS: dict[str, str] = {}


def _id(record: dict) -> str:
    return str(record.get("job_id") or record.get("id") or "")


def issue(record: dict) -> str:
    """Make the current client the owner of a new job record (before it is written)."""
    from rusticre import hydra
    token = secrets.token_hex(16)
    who = hydra.identity()
    record["owner"] = {"client": who["client"], "harness": who["harness"],
                       "token_sha256": hashlib.sha256(token.encode()).hexdigest()}
    _TOKENS[_id(record)] = token
    return token


def check(record: dict, token: str = "") -> None:
    """Refuse a cancel by anyone but the job's owner. Jobs made before owners existed are open."""
    owner = record.get("owner")
    if not isinstance(owner, dict) or not owner.get("token_sha256"):
        return
    supplied = token or _TOKENS.get(_id(record), "")
    if supplied and hmac.compare_digest(hashlib.sha256(supplied.encode()).hexdigest(), owner["token_sha256"]):
        return
    raise PermissionError("job %s belongs to %s (%s); every client may read it, cancelling it needs owner, the token "
                          "its start returned" % (_id(record), owner.get("client"), owner.get("harness")))


def public(record: dict) -> dict:
    """A job as every client sees it: the owner's identity, never the token's hash."""
    owner = record.get("owner")
    if isinstance(owner, dict) and "token_sha256" in owner:
        record = {**record, "owner": {key: value for key, value in owner.items() if key != "token_sha256"}}
    return record
