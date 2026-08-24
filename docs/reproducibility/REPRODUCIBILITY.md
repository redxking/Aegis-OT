# Reproducibility Protocol

Every reported experiment must include a manifest with the Git commit, dirty-tree
state, UTC timestamp, scenario catalog and hash, all master seeds, baselines,
policy, kernel and oracle versions, source hashes, host information, raw-data
location, result hashes, known limitations, and analyst.

Raw result files are append-only research evidence. Derived summaries and figures
must be generated from raw files by committed code. Timing comparisons may vary
by host and load. The raw hash includes timing; the deterministic outcome hash
excludes timing and is the cross-run outcome-reproduction check.

Formal model-check evidence must record the TLC version, model hash, configuration, state count, runtime, invariant result, and any counterexample trace. Passing only the intended model is insufficient; weakened variants must produce expected counterexamples.
