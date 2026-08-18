# AgentGym

AgentGym is a deterministic adversarial benchmark for authorization and
information-flow failures in agentic systems. It runs fourteen boundary
scenarios — each a benign task plus a matched attack — through real agent
framework runtimes under four enforcement modes, and judges every run by its
observable side effects, not by what the agent claims.

- Project goal and scenario design: [AGENTGYM.md](AGENTGYM.md).
- How to read the results and defend every number: [docs/EXPLANATION.md](docs/EXPLANATION.md).

## Enforcement modes

| Mode | What it is |
| --- | --- |
| `native` | A representative weak integration — the named baseline floor. |
| `opa` | Open Policy Agent (container) with an honest Rego translation of the policy. |
| `cerbos` | Cerbos (container) — a second, structurally different industry engine. |
| `typesec` | The reference substrate: the compiled Rust ToolGate + ODRL engine, composed with the provider clients and mediating execution. |

`native` and `typesec` run in-process. `opa` and `cerbos` are real containers
that answer real decision requests; they block every attack whose adversarial
value is visible in the dispatch-time request and fail exactly the ones whose
deciding fact only exists at execution — the boundary AgentGym exists to draw.

## Run it

In-process matrix (no services, no keys):

```bash
uv sync --extra frameworks --extra test
uv run pytest
uv run agentgym                 # native + typesec across all frameworks
uv run agentgym --explain       # per-case reasoning
cargo test --manifest-path rust/Cargo.toml
```

Full four-mode matrix with the live engines and wire-faithful WorkOS / Arcade
emulators, all on one Docker network:

```bash
docker compose run --rm bench   # native, opa, cerbos, typesec
```

The suite implements BG-01 through BG-14 for real deterministic Pydantic AI,
LangChain, and CrewAI tool runtimes, enforced at each framework's own
pre-tool hook. WorkOS and Arcade are deterministic emulators of the current
provider contracts (WorkOS `/authorization/*`, Arcade `/v1/tools/*`),
including timeout, malformed-response, stale-allow, user-swap, and
resource-confusion faults. No provider credentials or model API keys are
required.

The `native` result is a baseline, not a claim about the strongest custom
security integration possible in each framework. The competitor engine modes
are configured with the strongest honest translation of the policy; where
they fail is structural, not a misconfiguration.

## License

MIT.
