# AgentGym: the full deterministic matrix in one container.
#
# The image reproduces the host layout exactly — /work/typesec is a pinned
# clone of the sibling checkout that pyproject's uv source points at — so
# `uv sync` builds the same editable Rust/PyO3 typesec wheel inside the
# image that developers build outside it. One image runs the Python suite,
# the benchmark CLI, the provider emulators, and the Rust compile-fail
# tests; docker-compose.yml wires the competitor policy engines beside it.

FROM python:3.13-bookworm

# Pinned to typesec main's 0.13.1 release commit — a stable, fetchable ref
# exposing the same ToolGate / TypesecGate / validate API the host build
# uses. The in-image `test` entrypoint reruns pytest to confirm the pinned
# version stays API-compatible with the adapter.
ARG TYPESEC_REV=d63789a03cfc0ea1de0f52236454d3f734693d5d

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential curl git pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Rust toolchain for the typesec PyO3 wheel and the compile-fail suite.
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.96.0
ENV PATH="/root/.cargo/bin:${PATH}"

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /work
RUN git clone https://github.com/querygraph/typesec.git typesec \
    && git -C typesec checkout "${TYPESEC_REV}"

WORKDIR /work/adversarial-agents
COPY pyproject.toml uv.lock .python-version ./
COPY agentgym ./agentgym
COPY tests ./tests
COPY policy ./policy
COPY fixtures ./fixtures
COPY rust ./rust
COPY scripts ./scripts

# Cache-mounted so a rebuild reuses the resolved framework wheels and the
# compiled typesec artifacts instead of re-downloading and recompiling.
ENV UV_LINK_MODE=copy
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=cache,target=/work/typesec/target \
    uv sync --extra frameworks --extra test

ENTRYPOINT ["scripts/docker-entry.sh"]
CMD ["benchmark"]
