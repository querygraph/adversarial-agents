# syntax=docker/dockerfile:1.7
# Reproducible AgentGym image: immutable base images, repository-local Rust
# source, Cargo/uv locks, and a prebuilt protected-gate companion wheel.

# This digest freezes maturin 1.14.1 and its complete Rust/Python build image.
FROM ghcr.io/pyo3/maturin:v1.14.1@sha256:2665227312dd1eab1c29c70a001dc8aac53155a2d048bede3b2df7f1691c8e38 AS wheel-builder

ARG TARGETARCH

WORKDIR /src
COPY native ./native

RUN --mount=type=cache,id=agentgym-native-target-${TARGETARCH},target=/src/native/target \
    --mount=type=cache,id=agentgym-cargo-registry,target=/root/.cargo/registry \
    maturin build --locked --release \
        --interpreter /opt/python/cp313-cp313/bin/python \
        --manifest-path native/Cargo.toml \
        --out /wheels

# The tag documents the human-readable version; the digest makes it immutable.
FROM python:3.13.7-bookworm@sha256:c900d35aba5fe4c1dc1cd358408baae2902ff2a2926a1d15cc5002c6061ddb2e

COPY --from=ghcr.io/astral-sh/uv:0.11.32@sha256:df4cae8f3a96d175e2e5f992e597550000edbe78fdc2594d5cd8de1a217f504c /uv /usr/local/bin/uv
COPY --from=wheel-builder /wheels /wheels

WORKDIR /work/adversarial-agents
ENV OTEL_SDK_DISABLED=true \
    AGENTGYM_TYPESEC_REVISION="typesec-core@0.13.1;typesec-rbac@0.13.1;typesec-odrl@0.13.1;querygraph-agentgym-native@0.3.0"
COPY pyproject.toml uv.lock .python-version ./
COPY agentgym ./agentgym
COPY tests ./tests
COPY policy ./policy
COPY fixtures ./fixtures
COPY scripts ./scripts
COPY native ./native

# Export exact versions and hashes from the committed lock. The local native
# package is omitted from registry sync because its exact wheel was built above.
RUN uv export --frozen --extra typesec --extra test \
        --no-emit-project --no-emit-package querygraph-agentgym-native \
        --format requirements-txt --output-file /tmp/runtime.lock \
    && uv venv /work/adversarial-agents/.venv \
    && uv pip sync --python /work/adversarial-agents/.venv/bin/python \
        --require-hashes /tmp/runtime.lock \
    && uv pip install --python /work/adversarial-agents/.venv/bin/python \
        --no-deps /wheels/querygraph_agentgym_native-0.3.0-*.whl \
    && VIRTUAL_ENV=/work/adversarial-agents/.venv uv pip install \
        --python /work/adversarial-agents/.venv/bin/python \
        --no-build-isolation --no-deps . \
    && /work/adversarial-agents/.venv/bin/python -c \
        "from agentgym.world import WORLD; from agentgym_native import AgentGymGate; assert WORLD.policy_digest; assert AgentGymGate"

ENTRYPOINT ["scripts/docker-entry.sh"]
CMD ["benchmark"]
