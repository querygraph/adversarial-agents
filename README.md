# AgentGym

AgentGym is a deterministic adversarial benchmark for authorization and
information-flow failures in agentic systems. It runs fourteen boundary
scenarios — each a benign task plus a matched attack — through three framework
interception paths under eight enforcement modes, and judges every run by its
observable side effects, not by what the agent claims.

The corpus has 28 scenario cases plus 12 provider-fault cases. Applicability
produces 846 rows in the complete three-framework/eight-profile matrix; TypeSec
runs all 40 cases per framework.

- Project goal and scenario design: [AGENTGYM.md](AGENTGYM.md).
- How to read the results and defend every number: [docs/EXPLANATION.md](docs/EXPLANATION.md).

## Enforcement modes

| Mode | What it is |
| --- | --- |
| `native` | A representative weak integration — the named baseline floor. |
| `workos` | Direct WorkOS provider authorization, scored as its own peer track. |
| `arcade` | Direct Arcade tool authorization, scored as its own peer track. |
| `opa` | Open Policy Agent (container) with an honest Rego translation of the policy. |
| `cerbos` | Cerbos (container) — a second, structurally different industry engine. |
| `opa-mediated` | OPA plus the same execution mediator used for the substrate ablation. |
| `cerbos-mediated` | Cerbos plus that identical execution mediator. |
| `typesec` | The reference composition: this repository's custom compiled Rust `AgentGymGate`, built on TypeSec RBAC/ODRL engines and composed with provider clients and mediating execution. |

The native, provider-only, and TypeSec tracks run in-process. OPA and Cerbos
are real containers. The mediated variants are the required ablation: they
hold the application execution layer constant instead of attributing every
mediator advantage to the underlying policy engine.

## Run it

In-process matrix (no services, no keys):

```bash
uv sync --frozen --extra typesec --extra test
uv run pytest
uv run agentgym                 # all four in-process modes across all frameworks
uv run agentgym --explain       # per-case reasoning
uv run agentgym --framework pydantic-ai --mode typesec --check --require-fail-closed
cargo test --locked --manifest-path rust/Cargo.toml
```

`--check` is the release/CI gate: it exits nonzero if any selected score falls
below its configured thresholds. `--require-fail-closed` also prevents an
accidentally filtered or incomplete corpus from omitting the scored fault
trials and reporting that metric as unavailable.

## Installable artifacts

The pure-Python AgentGym wheel contains its fixtures and policies and installs
without a source checkout or Rust toolchain:

```bash
uv sync --frozen --extra test
uv build --wheel --no-build-isolation
python -m pip install dist/querygraph_agentgym-0.3.0-py3-none-any.whl
agentgym --help
agentgym --framework pydantic-ai --mode native --json
```

The Rust TypeSec substrate is an exact, optional companion wheel rather than
an unresolvable base dependency. It is built from `native/` using exact
crates.io TypeSec components and the committed Cargo lock:

```bash
scripts/build_native_wheel.sh dist
python -m pip install --find-links dist 'querygraph-agentgym[typesec]==0.3.0'
agentgym --framework pydantic-ai --mode typesec --check --require-fail-closed
```

The development override in `pyproject.toml` resolves the same companion from
this checkout's `native/` directory. It never silently substitutes a weaker
mode when the Rust extension is unavailable.

The companion's deterministic receipt key is a public benchmark fixture. It
makes exact-call and tamper verification reproducible; it is not evidence of
production issuer trust or key custody. Production use requires a protected
issuer key or TypeSec's production receipt mechanism.

Full eight-mode matrix with the live engines and wire-faithful WorkOS / Arcade
emulators, all on one Docker network:

```bash
docker compose run --rm bench
```

The suite implements BG-01 through BG-14 through deterministic Pydantic AI and
LangChain scripted runtimes plus CrewAI's offline hook-bearing executor helper,
enforced at each framework's documented pre-tool interception surface. It does
not run a full `Crew.kickoff()` model loop. WorkOS and Arcade are deterministic
emulators of the current provider contracts (WorkOS `/authorization/*`, Arcade
`/v1/tools/*`),
including timeout, malformed-response, stale-allow, user-swap, and
resource-confusion faults. No provider credentials or model API keys are
required.

The `native` result is a baseline, not a claim about the strongest custom
security integration possible in each framework. The competitor engine modes
use generated policy translations. Raw-PDP and commonly mediated results are
reported separately, so a gap is attributed to the named integration profile
rather than to an inherent limitation of OPA, Cerbos, WorkOS, or Arcade.

## License

MIT.
