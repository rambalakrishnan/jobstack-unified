"""Stub implementations of workflow_runtime's CONSUMES dependencies.

Each submodule mirrors one CONSUMES dependency and exposes exactly the
declared signatures with deterministic in-memory behavior. No I/O, no
network, no imports from ``src`` (the composition root).
"""
