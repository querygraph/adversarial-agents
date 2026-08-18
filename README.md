# AgentGym

AgentGym is a deterministic adversarial benchmark for authorization and
information-flow failures in agentic systems. Its project goal and full
scenario design are in [AGENTGYM.md](AGENTGYM.md).

Install all deterministic peer runtimes and run the complete matrix:

```bash
uv sync --extra frameworks --extra test
uv run pytest
uv run agentgym
uv run agentgym --framework pydantic-ai --mode typesec --json
cargo test --manifest-path rust/Cargo.toml
scripts/check.sh
```

The suite implements BG-01 through BG-14 for real deterministic Pydantic AI,
LangChain, and CrewAI tool runtimes in two modes: a representative weak native
Python baseline and a protected mode connected to TypeSec's compiled Rust/PyO3
`ToolGate` and ODRL engine. The native result is a baseline, not a claim about
the strongest custom security integration possible in each framework.

WorkOS and Arcade are deterministic emulators in CI, including timeout,
malformed-response, stale-allow, user-swap, and resource-confusion cases. No
provider credentials or model API keys are required.

The acceptance script also tests TypeSec's Python crate and provider integration
crate in the sibling TypeSec checkout.

## License

MIT.
