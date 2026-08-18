# Running the matrix in Docker

The full four-mode matrix runs on one Docker network, like catalog-bench and
adversarial-cognition:

```bash
docker compose run --rm bench
```

This brings up Open Policy Agent, Cerbos, and both provider emulators as
sidecars, then runs all 336 case-runs (3 frameworks × 4 modes × 28 cases)
against them. The resulting safety scores match the host-measured results in
`results/agentgym-2026-08-17.json` exactly across all twelve framework × mode
configurations (`results/agentgym-docker-2026-08-17.json` is the containerized
run).

Other entry points on the same image:

```bash
docker compose build                       # build the image
docker run --rm agentgym:dev test          # pytest + in-image typesec wheel check
docker run --rm agentgym:dev benchmark --mode default   # native + typesec only
```

## How the typesec wheel is handled

The `native` and `typesec` modes import the compiled `typesec` PyO3
extension. `typesec` is **not on PyPI**, and building it from source is not
self-contained: its Cargo workspace path-depends on the **`grust`** sibling
repository. So the image uses a **two-stage build**:

1. A **builder stage** clones `typesec` and `grust` at the exact revisions the
   published results were measured against and runs `maturin` to produce the
   linux `typesec` wheel. The heavy grust graph backends (`grust-graph`,
   lancedb/surreal) are optional and off, so this is a moderate Rust compile,
   cached as a layer — subsequent image builds reuse it.
2. A **runtime stage** installs that prebuilt wheel plus the framework deps,
   with no Rust toolchain and no sibling checkouts. It is slim, and its build
   is fast once the builder layer is cached.

The in-image `test` entrypoint reruns pytest against the wheel, so a pin bump
that broke API compatibility with the adapter would fail the build.

To repin the typesec/grust revisions (e.g. to a future release), pass build
args: `docker build --build-arg TYPESEC_REV=… --build-arg GRUST_REV=… .`
(with the matching `*_BRANCH` args if the commits are not on the default
branch). The durable long-term option remains publishing a linux `typesec`
wheel to an index, which would remove the builder stage entirely.

## Reproducing without Docker

Bring up OPA, Cerbos, and the emulators (or their standalone binaries), point
`AGENTGYM_OPA_URL` / `AGENTGYM_CERBOS_URL` at them, and run
`uv run agentgym --mode all` on a host that has the `typesec` editable install
with `grust` alongside it.
