# Development

Building, testing, and extending the harness. Grounded in the workspace `Cargo.toml` and the crate layout.

## Requirements

The project needs Rust edition 2024 (Cargo 1.85 or newer). It also needs OpenSSL headers and `pkg-config` at build time, because `turbomcp` (used by the MCP crate) pulls `reqwest` with its default native-TLS backend. On a NixOS or nix-managed host, build inside a shell that provides them:

```bash
nix-shell -p openssl pkg-config --run 'cargo build --workspace'
```

On Debian or Fedora, install `libssl-dev` / `pkg-config` (or `openssl-devel` / `pkgconf-pkg-config`) once and build normally.

## Workspace layout

| Crate | Role |
|---|---|
| `crates/harness` | Cedar engine, entity and trajectory stores, tarpc server, adjudication |
| `crates/config` | layered environment loader (system then user) |
| `crates/common` | stdin/stdout JSON, tracing init, shared hook client plumbing |
| `crates/guardrails/llm` | multi-provider structured-output LLM client |
| `crates/guardrails/signature` | YARA-X signature engine, rules embedded at compile time |
| `crates/guardrails/ifc` | data-sensitivity (IFC) classifier |
| `crates/guardrails/policy` | secure-code policy classifier |
| `crates/mcp` | MCP server for Cedar policy authoring |
| `apps/claude`, `apps/cursor`, `apps/copilot`, `apps/gemini`, `apps/opencode` | per-agent hook adapters |

## Build and test

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

Clippy requires the `clippy` rustup component; install it with `rustup component add clippy` if `cargo clippy` reports the command missing.

The LLM-dependent integration tests are marked `#[ignore]` because they need a live provider. Run them with a configured environment:

```bash
# configure a provider in ~/.sondera/env (or /etc/sondera/env), then:
cargo test --workspace -- --ignored

# the live Vertex test needs ADC plus the Vertex env vars:
cargo test -p sondera-llm --lib vertex::tests::live_dedicated_endpoint_classifies -- --ignored
```

## Fork relationship

This repository is a fork of `sondera-ai/sondera-coding-agent-hooks`. The upstream remote points at the original, so you can pull in changes:

```bash
git remote -v                              # upstream -> sondera-ai/...
git fetch upstream
git merge upstream/main                    # or rebase
```

Resolve conflicts in the guardrail crates and the harness where this fork diverges (the multi-provider LLM client, the fail-mode logic, the layered config loader). Keep commits focused; the history uses conventional-commit prefixes (`feature(...)`, `fix(...)`, `docs:`).

## Extending

- Add a provider: see the backends in `crates/guardrails/llm/src/` and the `Provider` enum in `lib.rs`. The OpenAI-compatible backend covers any provider that speaks Chat Completions.
- Add a YARA rule: drop a `.yar` file in `crates/guardrails/signature/rules/` and rebuild (see `docs/guardrails.md`).
- Add a Cedar policy: drop a `.cedar` file in the policy directory and restart (see `docs/policies.md`).
- Tune the classifiers: edit `policies/ifc.toml` and `policies/policies.toml` (see `docs/guardrails.md`).

## Running by hand

To exercise the full loop without an agent, start the server and call an adapter directly:

```bash
sondera-harness-server -v &
echo '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' \
  | sondera-claude --verbose pre-tool-use
```

The adapter logs the normalized event and the decision on stderr.
