# AgentGym: the full deterministic matrix in one container.
#
# Two stages. The builder compiles the typesec PyO3 wheel once — typesec is
# not on PyPI, and its workspace manifest references the grust sibling repo,
# so both are cloned at the exact revisions the published results were
# measured against. The runtime stage installs that prebuilt wheel plus the
# framework deps, with no Rust toolchain and no sibling checkouts, so it is
# slim and its build is fast once the builder layer is cached. See
# docs/DOCKER.md for why the wheel is built rather than pulled.

# ---- stage 1: build the typesec wheel ---------------------------------------
FROM python:3.13-bookworm AS wheel-builder

# Revisions the host build and the committed results were measured against.
ARG TYPESEC_REV=669e105601c46aab0d11bcaaa4b06369f43bc934
ARG TYPESEC_BRANCH=agent/performance-benchmarks
ARG GRUST_REV=2698a0379da946df92e4db9457bd935b138b1c40
ARG GRUST_BRANCH=agent/marciana-production-path

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential curl git pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.96.0
ENV PATH="/root/.cargo/bin:${PATH}"
RUN pip install --no-cache-dir "maturin>=1.8,<2"

WORKDIR /src
# typesec's Cargo workspace path-depends on grust; both must be present for
# `cargo metadata` to resolve before maturin builds the extension.
RUN git clone --branch "${GRUST_BRANCH}" https://github.com/querygraph/grust.git grust \
    && git -C grust checkout "${GRUST_REV}"
RUN git clone --branch "${TYPESEC_BRANCH}" https://github.com/querygraph/typesec.git typesec \
    && git -C typesec checkout "${TYPESEC_REV}"

RUN --mount=type=cache,target=/src/typesec/target \
    --mount=type=cache,target=/root/.cargo/registry \
    maturin build --release \
        --manifest-path typesec/crates/typesec-python/Cargo.toml \
        --out /wheels

# ---- stage 2: slim runtime with the prebuilt wheel --------------------------
FROM python:3.13-bookworm

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
COPY --from=wheel-builder /wheels /wheels

WORKDIR /work/adversarial-agents
COPY pyproject.toml .python-version ./
COPY agentgym ./agentgym
COPY tests ./tests
COPY policy ./policy
COPY fixtures ./fixtures
COPY scripts ./scripts

# Install the prebuilt typesec wheel, then the framework deps and agentgym
# itself (no-deps, so the editable typesec source override in pyproject is
# never consulted). One venv at /work/adversarial-agents/.venv.
ENV UV_PROJECT_ENVIRONMENT=/work/adversarial-agents/.venv
RUN uv venv "${UV_PROJECT_ENVIRONMENT}" \
    && uv pip install /wheels/typesec-*.whl \
    && uv pip install \
        "crewai>=1.15,<2" "langchain>=1.3,<2" "langgraph>=1.2,<2" \
        "pydantic-ai-slim>=2.31,<3" "pytest>=8" "pytest-asyncio>=1" "pyyaml>=6" \
    && uv pip install --no-deps .

ENTRYPOINT ["scripts/docker-entry.sh"]
CMD ["benchmark"]
