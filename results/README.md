# AgentGym result artifacts

`agentgym-docker-2026-08-19.json` is the current schema-v2 live-container
matrix. It records every applicable case row plus the exact framework,
dependency, policy-corpus, scenario-corpus, TypeSec, service-image, benchmark
image, command, seed, commit, and working-tree provenance used for the run.
It contains 846 rows and 24 scores, was produced from clean commit
`75fc75caf9616b4a7d68b81ee4005c816d86b37d` and benchmark image
`sha256:97bc0e2e3435ec4f16447ea670c5070070236d5467f9e8882afccc6ccbdede08`,
and has file SHA-256
`9f1680c26dea33ba9c22308ed15273b5be5f2170ecff841c19108989f41f7495`.
An independent second full run with the same recorded inputs was byte-identical.

The two `2026-08-17` files are retained only as historical artifacts. They use
the earlier 336-row corpus and predate the audited scoring/provenance contract;
do not use them for current score or release claims.

A release report is authoritative only when its `provenance` object passes
`agentgym.runner.validate_provenance`, its image identifier matches the tested
artifact, and the repository's release gates pass for the same source tree.
