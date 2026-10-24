"""The systems a co-op library has to own, and the mod surfaces around them.

Status here is a starting label, not a measurement. A row becomes evidence
when `rusticre evidence add` stores the log line that proves it.

Full reverse engineering means one system at a time, with a prologue and a
source for every address. It does not mean decompiling every function in the
exe before the coop library can move.
"""

from __future__ import annotations

GAMES = {
    "cyberpunk": {
        "title": "Cyberpunk 2077",
        "exe_names": ["Cyberpunk2077.exe"],
        "exe_rel": "bin/x64/Cyberpunk2077.exe",
        "address_table": "cyberpunk2077_addresses.json",
        "note": "Night City Together. The coop library stays in that repo. This toolkit answers the engine questions.",
    },
    "kotor": {
        "title": "Star Wars: Knights of the Old Republic",
        "exe_names": ["swkotor.exe"],
        "exe_rel": "swkotor.exe",
        "address_table": "",
        "note": "32-bit exe. Format parsers, the action table and the ledger stay in kotor-remaster.",
    },
    "swtor": {
        "title": "Star Wars: The Old Republic",
        "exe_names": ["swtor.exe"],
        "exe_rel": "swtor.exe",
        "address_table": "",
        "note": "Protocol decoders and the shard server stay in SWTOR-origins. Point ghidra at the analysed client.",
    },
}

# status: open = not yet proved in the ledger. partial = a doc or a port exists
# and still has open rows. The words are a map, not an acceptance result.
SYSTEMS = [
    {
        "game": "cyberpunk",
        "id": "player-body",
        "status": "partial",
        "need": "The other player's V is the real body: gender, slots, meshes, hair, gear. Items that are not components arrive as items.",
    },
    {
        "game": "cyberpunk",
        "id": "player-animation",
        "status": "partial",
        "need": "Replay the owner's animgraph inputs on the puppet. Armed aim, gait, feet and sway still need the owner's eyes. Do not invent a second graph.",
    },
    {
        "game": "cyberpunk",
        "id": "player-movement",
        "status": "partial",
        "need": "One owner. The receiver interpolates. The mover rewrites the root, so position is written after it, not by a second simulation.",
    },
    {
        "game": "cyberpunk",
        "id": "world-streaming",
        "status": "open",
        "need": "Each player streams the world around their own body. The guest must not be limited to whatever the host camera has loaded.",
    },
    {
        "game": "cyberpunk",
        "id": "new-game",
        "status": "open",
        "need": "Both players start one new game and share the prologue facts, the way a party starts in Baldur's Gate. Find the writer of those facts before syncing them.",
    },
    {
        "game": "cyberpunk",
        "id": "quests",
        "status": "open",
        "need": "Journal facts, checkpoints and mission state are one copy. On join, the guest follows the host's world, not only the clock, the weather and the tracked quest.",
    },
    {
        "game": "cyberpunk",
        "id": "scenes",
        "status": "open",
        "need": "Dialogue, cutscenes and braindances play for both, with each player's own V present. A scene cannot play while quest facts differ.",
    },
    {
        "game": "cyberpunk",
        "id": "vehicles",
        "status": "partial",
        "need": "Host-arbitrated epochs. Static cars are adopted, not duplicated.",
    },
    {
        "game": "cyberpunk",
        "id": "npcs",
        "status": "partial",
        "need": "One owner, replay of the action, no second AI brain on the receiver.",
    },
    {
        "game": "cyberpunk",
        "id": "combat",
        "status": "partial",
        "need": "Hits, status effects and the drawn weapon agree, including the parts the puppet can actually render.",
    },
    {
        "game": "kotor",
        "id": "formats",
        "status": "partial",
        "need": "GFF, 2DA, KEY/BIF, NCS and the save VFS, each with a corpus check. The exe map is the action table and the engine functions those formats call.",
    },
    {
        "game": "kotor",
        "id": "engine",
        "status": "open",
        "need": "The new engine consumes proved formats and proved functions. A full function export is a cache, not the engine.",
    },
    {
        "game": "swtor",
        "id": "protocol",
        "status": "partial",
        "need": "Opcodes, GOM fields and the area/character/combat paths the private server must answer. Cite a capture line or a decompile line.",
    },
    {
        "game": "swtor",
        "id": "client-native",
        "status": "partial",
        "need": "The analysed Ghidra project stays read-only. Scripts such as Recv.java run on a lane copy.",
    },
]

MODS = [
    {
        "id": "red4ext",
        "keep": True,
        "need": "The loader other mods use. Keep it. Our plugin lives on it. Re-derive every hash against the installed exe.",
    },
    {
        "id": "redscript",
        "keep": False,
        "need": "The script host. Both peers must compile the same bundle. Replacement target: stop depending on a fork's private fixes, and still load other mods' scripts when both players have the same set.",
    },
    {
        "id": "codeware",
        "keep": False,
        "need": "ScriptableService, entity attach, ink widgets, input. Replacement target. Until it is replaced, both peers use the same build and we do not wrap a method that build already wraps.",
    },
    {
        "id": "tweakxl",
        "keep": False,
        "need": "TweakDB flats and records. Replacement target: read the same yaml both peers have. Coexist until then.",
    },
    {
        "id": "archivexl",
        "keep": False,
        "need": "Extra archives and dynamic appearances. Coexist: our archive plus the same XL set on both peers. Replacement is later.",
    },
    {
        "id": "cet",
        "keep": False,
        "need": "Not a dependency. Ignore it unless a shared mod needs it, in which case both peers have it and we do not hook its console.",
    },
]


def systems_text(game: str = "") -> str:
    rows = [row for row in SYSTEMS if not game or row["game"] == game]
    if game and game not in GAMES:
        raise ValueError("unknown game %s; choose %s" % (game, ", ".join(GAMES)))
    lines = ["# systems"]
    for row in rows:
        lines.append("%s %s [%s] %s" % (row["game"], row["id"], row["status"], row["need"]))
    lines.append("")
    lines.append("# mods (cyberpunk compatibility)")
    lines.append("A mod is allowed when both peers have the same build. A mod we require is a replacement target.")
    for row in MODS:
        mark = "keep" if row["keep"] else "replace"
        lines.append("%s [%s] %s" % (row["id"], mark, row["need"]))
    return "\n".join(lines)


def games_text() -> str:
    lines = []
    for key, row in GAMES.items():
        lines.append("%s: %s" % (key, row["title"]))
        lines.append("  exe: %s" % row["exe_rel"])
        lines.append("  %s" % row["note"])
    return "\n".join(lines)
