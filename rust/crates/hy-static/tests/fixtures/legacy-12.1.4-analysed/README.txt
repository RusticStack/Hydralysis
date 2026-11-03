A Ghidra 12.1.4 project (program database version 32), made by make_legacy_fixture.py
from flow_fixture.exe (sha256 d105b8ad8a5f549a8a2c205e95f71e1b84bcc7ec183f63ea9804442be855179b), a PE compiled by us from a few
lines of C. It holds nothing derived from a game. Never open it writable in place:
the tests copy it first.

Analysed: stock 12.1.4 auto-analysis with its default analysers (analyzeHeadless
without -noanalysis), so Hydralysis can adopt it and commit to a new generation
(PROTOCOL-3.md gate 9.6). The unanalysed legacy-12.1.4 beside it stays as it is.
Recipe (Ghidra/Features/HeadlessSession):

    python examples/make_legacy_fixture.py --analysed --stock <stock 12.1.4 install>
        --exe flow_fixture.exe --stock-zip ghidra_12.1.4_PUBLIC_20260921.zip

which runs, with its own empty APPDATA, LOCALAPPDATA and TEMP:

    analyzeHeadless <tmp>/project legacy -import flow_fixture.exe -overwrite

Stock install: the official release ghidra_12.1.4_PUBLIC_20260921.zip
(github.com/NationalSecurityAgency/ghidra, tag Ghidra_12.1.4_build),
SHA-256 ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db, checked against the published value.
