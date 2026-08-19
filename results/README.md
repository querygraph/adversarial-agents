# AgentGym result artifacts

`agentgym-docker-2026-08-19.json` is the current schema-v2 live-container
matrix. It records every applicable case row plus the exact framework,
dependency, policy-corpus, scenario-corpus, TypeSec, service-image, benchmark
image, command, seed, commit, and working-tree provenance used for the run.

The two `2026-08-17` files are retained only as historical artifacts. They use
the earlier 336-row corpus and predate the audited scoring/provenance contract;
do not use them for current score or release claims.

A release report is authoritative only when its `provenance` object passes
`agentgym.runner.validate_provenance`, its image identifier matches the tested
artifact, and the repository's release gates pass for the same source tree.
