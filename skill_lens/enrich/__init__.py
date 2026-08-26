"""Opt-in enrichment adapters (SPEC §4 E8 / §14 G2).

Every module under this package is OUTSIDE the default import closure by
law: the deterministic pipeline never imports it, and the import-contract
test (G1/G3) fails the build if that ever drifts. Adapters load ONLY inside
explicitly flagged codepaths (``--osv`` / ``/lens scan … osv:true``) and
their outputs are tagged ``enriched=true`` per G2.
"""
