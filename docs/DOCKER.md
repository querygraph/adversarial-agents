# Running the matrix in Docker

The four-mode matrix is designed to run on one Docker network, like
catalog-bench and adversarial-cognition: `docker-compose.yml` wires the two
competitor engines and both provider emulators beside the benchmark image.

## What runs in Docker cleanly today

- **Open Policy Agent** (`openpolicyagent/opa:1.19.1`) and **Cerbos**
  (`ghcr.io/cerbos/cerbos:0.55.0`) come up from their standard images and
  serve the checked-in policies. Both were validated against their real
  binaries: they return the designed decisions for every representative
  request (see the offline checks in the commit history).
- The **provider emulators** are pure-stdlib HTTP servers with no native
  dependencies.

## The one build dependency: the typesec wheel

The `native` and `typesec` modes import the compiled `typesec` PyO3
extension. `typesec` is **not published to PyPI**, and building it from
source is not self-contained: the `typesec` Cargo workspace has a member
(the umbrella `typesec` crate, via `typesec-agent`) that path-depends on the
**`grust`** sibling repository (`grust-cypher` → `grust-core` +
`grust-memory`). So `cargo metadata` — which maturin runs over the whole
workspace — fails inside an image that clones only `typesec`, and providing
`grust` pulls a slice of the graph-engine workspace into the compile.

This is the reason a naive `uv sync` in the image is heavy, and it is a
packaging decision, not a benchmark-correctness one: **the measured
four-mode results in `results/` were produced against the real OPA and
Cerbos engines**, with `typesec` built the way the host builds it (the
editable workspace install, with `grust` present as a sibling).

### Two clean ways to close it

1. **Publish a linux `typesec` wheel** (to an internal index or as a CI
   build artifact) and depend on it in the image instead of the editable
   source. This is the durable fix — the image then needs no Rust toolchain
   and no sibling repos, and the build is fast and hermetic. It also pins
   the exact security-relevant `typesec` version into the published result.
2. **Clone `typesec` and `grust` at compatible pinned revisions** into the
   image and build the wheel there. This works but compiles a slice of the
   grust workspace; give the Docker VM enough memory, and pin both repos to
   the revisions the published result was measured against.

Until one of those lands, reproduce the full matrix the way the committed
results were produced: bring up OPA, Cerbos, and the emulators (compose, or
the standalone binaries), point `AGENTGYM_OPA_URL` / `AGENTGYM_CERBOS_URL`
at them, and run `uv run agentgym --mode all` on a host that has the
`typesec` editable install with `grust` alongside it.
