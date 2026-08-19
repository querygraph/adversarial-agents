# Running the matrix in Docker

The full eight-mode matrix runs on one Docker network, like catalog-bench and
adversarial-cognition:

```bash
docker compose run --rm bench
```

This brings up Open Policy Agent, Cerbos, and both provider emulators as
sidecars, then scores native, WorkOS, Arcade, OPA, Cerbos, both equal-mediator
ablations, and TypeSec across every framework and applicable case. The final
corpus is 28 scenario cases plus 12 provider faults: applicability yields 846
rows across three frameworks and eight profiles, with all 40 cases applied to
TypeSec per framework. Committed reports are historical artifacts; a new
release report must carry its own commit, corpus digests, dependency versions,
and service-image provenance.

Other entry points on the same image:

```bash
docker compose build                       # build the image
docker run --rm agentgym:dev test          # pytest + in-image Rust companion check
docker run --rm agentgym:dev benchmark --mode default   # four in-process modes
```

## How the Rust companion wheel is handled

The portable `querygraph-agentgym` wheel deliberately has no unpublished base
dependency. The protected mode loads `querygraph-agentgym-native`, a small
custom PyO3 `AgentGymGate` built from this repository's `native/` crate on top
of the TypeSec policy engines. That crate depends on
the exact published `typesec-core`, `typesec-rbac`, and `typesec-odrl` 0.13.1
components and has its own committed Cargo lock; it has no sibling checkout or
hidden path dependency.

Its receipt key is deliberately public and deterministic for reproducible
benchmark verification. The Docker result measures exact-call binding and
tamper rejection, not production issuer trust; deployments require protected
key custody or TypeSec's production receipt mechanism.

The image uses two immutable stages:

1. A digest-pinned `maturin:1.14.1` builder compiles `native/` with
   `--locked` for CPython 3.13.
2. A digest-pinned Python 3.13.7 runtime exports every framework and test
   dependency, including hashes, from AgentGym's committed `uv.lock`, then
   installs the companion and portable AgentGym wheels without re-resolution.

The in-image `test` entrypoint reruns pytest against the wheel, so a pin bump
that broke API compatibility with the adapter would fail the build.

To update the native substrate, change and review `native/Cargo.toml` and
`native/Cargo.lock` together, then let CI exercise the base-only wheel, local
wheelhouse extra resolution, and protected matrix. Tag builds publish both
platform companion wheels beside the portable AgentGym artifact.

## Reproducing without Docker

Bring up OPA, Cerbos, and the emulators (or their standalone binaries), point
`AGENTGYM_OPA_URL` / `AGENTGYM_CERBOS_URL` at them, and run
`uv sync --frozen --extra typesec --extra test` followed by
`uv run agentgym --mode all`. For a checkout-free install, run
`scripts/build_native_wheel.sh` and install
`querygraph-agentgym[typesec]` from that local wheelhouse.

Both provider emulators now have real readiness probes, and `bench` waits for
OPA, Cerbos, WorkOS, and Arcade to report healthy before the matrix starts.
The CI workflow validates Compose, builds the immutable image, runs the live
four-engine matrix, and separately enforces the protected-score thresholds.
