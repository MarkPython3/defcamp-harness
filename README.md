# defcamp-harness (calc-v8)

Autonomous AI agent (Docker image) for the AISafe Agentic CTF at DefCamp.

## Strategy
- **Deterministic recon first, 0 model calls**: read `/code`, probe `$TARGETS`, run category-specific recon (pwn/rev/crypto/web) and auto-submit any `flag{32hex}` found in plain sight or split across surfaces.
- **Layered decode brute-forcer** (`solvers/layers.py`): tries op-chains (hex, base64, base32, base85, rot13, reverse, caesar, zlib, gzip, binary; depth 3) over every `/code` file and every target HTTP path / TCP banner. Catches multi-layer encodings without touching the (weak, shared) model.
- **Deterministic solvers** (`solvers/`, `angr_solve.py`): angr crackme solver, crypto/pwn batteries.
- **Constrained ReAct fallback**: only if deterministic paths fail, a bash + submit_flag loop with category-aware playbooks, retry-on-429/503, and health-based time budgeting.

## Build
```
docker build -t calc-v8 -f Dockerfile .
```
Entry: `node /app/agent.mjs`. Talks to the gateway via `$GATEWAY_URL` / `X-Run-Token`.
