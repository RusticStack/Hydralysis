---
name: rusticre-mod-compat
description: Decide whether Night City Together should keep, coexist with, or replace a framework mod. Use when the change touches RED4ext, redscript, Codeware, TweakXL, ArchiveXL, or CET.
---

# Same mods on both peers

`rusticre systems` ends with the mod table.

- RED4ext stays. It is the loader. Other people's mods need it. Every hash is re-derived against the installed exe (`rusticre hash`).
- redscript, Codeware, TweakXL, and ArchiveXL are replacement targets. Until each one is replaced, both players run the same build of it, and our code does not wrap a method that build already wraps.
- CET is not a dependency. Touch it only when a mod both players have requires it, and then do not hook its console.
- A mod we require in order to boot is a bug to schedule, not a feature.
- A mod that only one peer has installed is out of scope. Compatibility means the same set on both sides.

The replacement for a framework is the engine surface it was calling: entity attach, TweakDB flats, extra archives, the script host. Name that surface with `funcof` and an evidence row before deleting the dependency. Deleting the dependency in the same change as the discovery is how a patch breaks both the mod and everyone else's.
