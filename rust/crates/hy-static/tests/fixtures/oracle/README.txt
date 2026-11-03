oracleprog-legacy-12.1.4-analysed.txt: output of OracleProgram.java (Hydra Engine, Ghidra/Framework/HydraFormats/oracle)
run through stock Ghidra 12.2 ProgramDB (OpenMode.IMMUTABLE) on legacy-12.1.4-analysed/legacy.rep/idata/00/~00000000.db/db.1.gbf.
Copied from engine commit 75f489388b, testdata/oracleprog-legacy-12.1.4-analysed.txt. Rows are sorted by address text like the
oracle prints them; within one address the order is the order Java iterates.
flow_fixture.exe: the PE the fixture project was analysed from (sha256 d105b8ad8a5f549a8a2c205e95f71e1b84bcc7ec183f63ea9804442be855179b),
compiled by us from tests/fixtures/flow_fixture.c of Hydralysis; used as an independent oracle for bytes.
