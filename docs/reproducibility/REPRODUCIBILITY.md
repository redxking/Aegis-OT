# Reproducibility Protocol

Every reported experiment must include a manifest with the Git commit, dirty-tree state, UTC timestamp, scenario version, master and individual seeds, baseline, agent type, policy and safety versions, host information, raw-data location, result hash, known failures, and analyst.

Raw result files are append-only research evidence. Derived summaries and figures must be generated from raw files by committed code. Timing comparisons may vary by host and load; compare outcome hashes separately from latency values.

Formal model-check evidence must record the TLC version, model hash, configuration, state count, runtime, invariant result, and any counterexample trace. Passing only the intended model is insufficient; weakened variants must produce expected counterexamples.
