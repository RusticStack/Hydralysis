# Trace profiles

A profile adapts the generic Hydra semantic trace to one kind of target. It is a TOML file, bound to exact builds, that
says what to hook, what the events mean and how two runs are compared. Hydralysis loads and validates it
(`hydralysis.profiles`, `tomllib`), proves every hook against the build's bytes before a session starts, and records the
content hash of the profile in the session.

No target-specific profile ships with Hydralysis. A profile lives with the project it describes. The one file shipped here,
`src/hydralysis/profiles/baseline_fixtures.toml`, is for the test fixtures only and says so (`fixtures_only = true`).

## What a profile contains

```toml
[profile]
id = "my-app/1"                 # name/version; the session records id and content hash
domain = "app"                  # app | game | service | driver | other

[target]
bitness = 64                    # 32 or 64
modules = ["app.exe"]
[[target.builds]]               # a profile is build-bound: list every image it was verified against
module = "app.exe"
image_sha256 = "..."            # full SHA-256 of the image file
label = "1.2.3"

[host]
fault_policy = "tolerant"       # tolerant | fatal | freezes  (spec 15.1); a hook may override with `fault`
record_handler_chain = true     # record the VEH/UEF chain and debugger state at attach
# sampling = "adaptive"          # optional: adaptive (the default) thins a hot probe above rate_budget and counts every skip; exact never thins
# rate_budget = 120000          # kept records per second, all probes (docs/trace-overhead.md)

[[event_kinds]]                 # kinds in your namespace; they extend a core kind
name = "app.feature"            # <namespace>.<name>, lowercase, never core.*
extends = "core.state.write"
[event_kinds.payload]           # field -> type; a trailing ? makes it optional
feature = "key"                 # u8 u16 u32 u64 i32 i64 bool string key hex va bytes
enabled = "bool"

[[hooks]]
id = "feature-gate"
event = "app.feature"           # a core kind or a kind declared above
module = "app.exe"
required = true                 # a mismatch refuses the session; false: recorded as a coverage limitation
symbol = "FeatureGate"          # exactly ONE locator: symbol (export), rva (verified, build-bound) or signature
# rva = "0x1a2b0"
# signature = "48 89 5C 24 ?? 57"
prologue = ["48 89 5C 24 ??", "40 53 48 83 EC ??"]   # the exact accepted bytes at the site; ?? is a wildcard
prologue_offset = 0             # where the prologue starts, counted from the located site
capture = ["feature:key", "enabled:bool"]

[identity]                      # which resolver names a resource / state / object
resource = "path"               # built in: profile_module, profile_object_offset, path, handle, address, payload_field
state = "profile_object_offset"
[[resolvers]]                   # or your own, over payload fields
id = "feature_name"
kind = "state"
from = "payload.feature"
normalize = "lower"             # none | lower | basename | lower-basename

[[codecs]]                      # value codecs: hashed names, or a message layout (spec 14.5, 15.6)
id = "names64"
base = "fnv1a"                  # fnv1 | fnv1a | crc | murmur3_32 | layout
bits = 64
vectors = [{input = "a", output = "0xaf63dc4c8601ec8c"}]   # REQUIRED for a hash codec; all must reproduce
applies_to = ["app.feature.payload.feature"]

[[roles]]                       # thread roles (spec 15.2)
id = "main"
resolve = "function"            # thread_start_rva | thread_name | pool | function (the thread that ran hook X)
value = "frame-begin"

[[phases]]                      # frame and stage markers; events carry (frame, phase, role)
id = "frame"
kind = "frame"
open = "frame-begin"
close = "frame-end"

[diff]
group_by = ["kind", "resource.key", "function"]
align = ["phase", "frame_offset"]   # (frame offset, phase) is the cross-run key, never a timestamp

[[stores]]                      # persistent stores whose footprint a diff compares (spec 15.8)
id = "settings"
kind = "file"                   # file | registry | directory
path = "app.cfg"

[[bindings]]                    # script<->native registration (spec 15.7)
id = "vm-natives"
kind = "table"                  # table: table_rva, stride, name_offset, fn_offset, count?, argc_offset?
table_rva = "0x2000"
stride = 24
name_offset = 0
fn_offset = 8
argc_offset = 16
# kind = "call": register = "<hook id of the registration function>", name_arg, fn_arg, argc_arg?

[[queries]]                     # query modules: no catalog entry, no new tool
id = "app.registry.consumers"
kinds = ["core.resource.open"]
group_by = ["resource.key", "function"]
limit = 50
```

Unknown keys and unknown sections are refused, and so is a profile with any other problem: `ProfileError.errors` lists every
reason, not just the first.

## Verification

`hydralysis.profiles.verify_profile(profile, {module: Image})` checks every hook against the image bytes with the same code as
the `prologue` and `sigscan` tools:

1. the image must be a listed build of the right bitness;
2. the locator must resolve to one site (an export; a listed, verified RVA; a signature with exactly one hit);
3. the bytes there must equal one of the profile's `prologue` alternatives.

A hook that fails is **disabled and reported with its reason; it never guesses**.

| Hook | Mismatch means |
|---|---|
| `required = true` | `HookRefused` (`required_hook_refused`): the session or capability that depends on it is refused before anything opens |
| `required = false` | recorded as a coverage limitation with code `optional-hook-refused` (stored in evidence as `optional_hook_refused`); the session runs, and what it did not capture is stated |

### Probe parameters of a hook

A verified hook becomes a probe in the recorder (spec 5.1, WS-E). Besides the locator and the prologue a hook may say what to
record. All of it is bounded:

```toml
nargs = 3                       # 0..8 integer arguments recorded (default: as many as `capture` needs)
with_leave = true               # also record the return value, GetLastError and the time spent (implied by @ret)
buf = { arg = 0, max = 128 }    # a buffer argument: arg (pointer index), len_arg or fixed (length), wide (UTF-16), max <= 256
stack = 4                       # call-stack depth, 1..16 (1: the return address only); unwound from the .pdata, non-faulting
capture = ["path:string@0", "size:u32@2", "got:u32@ret"]   # name:type[@argN|@ret]; the position is the argument by default
```

A buffer is never stored as text: the event carries a keyed id and a length. A bounded, redacted preview (at most 256 bytes)
exists only for a probe named in the capture request's `authorize_preview`, and payload bytes only for one named in
`authorize_payload`.

### Fixtures-only profiles

The fixtures are built without a PDB and export none of the functions the baseline hooks. A profile with
`fixtures_only = true` therefore resolves a `symbol` that is not an export through the linker map the fixture build writes
beside the image (`frameloop.map` for `frameloop.exe`). Such a profile is the union of one section per fixture program: a run
supplies the images it uses, and the hooks of the other programs are `not-applicable`. A profile that is not `fixtures_only`
never reads a map and refuses a module it was not given as `module-unknown`.

`trace start` passes `options.profile` (a path, or `baseline`) and `options.images` (`{module: path}`). A build-bound profile
cannot be started without its images.

## Query modules

Two kinds, neither adds a tool to the catalog:

- **Declarative** (`kinds`, `group_by`, `filter`, `limit`): compiled into the `trace_query` request the engine already serves.
  Group keys are `kind`, `resource.key`, `function`, `state.key`, `process_id`, `process_gen`, `thread_id`, `thread_role`,
  `module`, `frame`, `phase`, `source_id` and `payload.<field>`.
- **Contained Python** (`module = "queries/top.py"`, `sha256 = "..."`): a function `query(rows, params) -> dict` over a bounded
  page of rows the engine already returned. It runs in a separate interpreter (`python -I`, an empty environment, a scratch
  directory, a timeout of 20 s), receives at most 4 MiB and returns at most 1 MiB of JSON, and only if the file still hashes
  to the value the profile pinned. It has no handle on the trace store, the engine connection or the target. A module must be
  a sibling file of a profile loaded from disk and inside its folder.

Run one with `trace query` and `options.profile`, `options.profile_query`.

## Hash codecs

A profile codec is a parameterised algorithm: an FNV with its own basis and prime, a CRC with its own polynomial, a Murmur
seed, with case folding and an encoding. It is refused unless it reproduces every test vector the profile gives, and it cannot
replace a built-in name. The built-ins are `fnv1a32`, `fnv1a64`, `fnv1_32`, `fnv1_64`, `crc32` and `murmur3_32`
(`hydralysis.trace_hashes`). The dictionary records the source of every name; two names with one hash are reported
`ambiguous` and neither is chosen.

## What the session records

`Profile.session_record()`: the profile id, the SHA-256 of the manifest and of every file it depends on (query modules), the
listed builds and whether it is `fixtures_only`. Changing one byte of the profile changes the recorded hash.
