#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / "scripts"))
from unpack_dag import SpecUnpacker

u = SpecUnpacker()
assert len(u.invariant_index) == 109, f"expected 109, got {len(u.invariant_index)}"
assert "BO-THREAD" in u.invariant_index, "BO-THREAD not indexed"
assert "BO-THREAD" in u.invariant_index["BO-THREAD"], "BO-THREAD value is placeholder, not rule text"
assert not u.errors, f"_build_indexes errors: {u.errors}"
print("[PASS] _build_indexes internal state correct")
