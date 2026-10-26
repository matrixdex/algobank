# Algobank

The design reference is `docs/ARCHITECTURE-v0.1.md`. Keep it a finished, polished reference, not a log of changes.

## Simplicity rule

Add complexity only when core Algobank functionality is impossible without it.

If a feature is possible without the complexity but needs more work (more rechecking, more computation), prefer the extra CPU cycles and keep the design simple.

Example: independent review of each function would let a function's result survive changes elsewhere, but rechecking the whole package gives the same answer. So independent function review is not added, and results stay keyed to the full Merkle hash.

Before proposing a new mechanism, ask: is this needed for core functionality, or does it only save computation? If it only saves computation, do not add it.
