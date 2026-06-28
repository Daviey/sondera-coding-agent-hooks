# opencode plugin for Sondera

This is the opencode-side glue for the Sondera harness. opencode loads this TypeScript plugin; the plugin spawns the Rust adapter (`apps/opencode`, binary `sondera-opencode-adapter`) which talks to the harness server over its Unix socket and returns an allow or deny. The adapter ships in the same repo and in the same releases as this plugin.

The wire contract between plugin and adapter is documented in [PROTOCOL.md](PROTOCOL.md). The broader Sondera architecture, policies, and guardrails are documented in [`docs/`](../../docs).

## Install

Quick install (downloads the adapter binary and the bundled plugin from the latest release):

```bash
curl -fsSL https://github.com/Daviey/sondera-coding-agent-hooks/raw/main/plugins/opencode/install.sh | bash
```

This puts the adapter in `~/.local/bin/sondera-opencode-adapter` and the plugin in `~/.config/opencode/plugins/sondera.ts`. opencode auto-loads `.ts` files from the plugins directory.

Or via npm:

```bash
npm install opencode-sondera
```

Then reference it in your opencode config:

```json
{ "plugin": ["opencode-sondera"] }
```

The harness server must be reachable. The plugin can auto-start it on first tool call if `harnessPath` is set (see configuration); otherwise start it yourself:

```bash
sondera-harness-server -v
```

Verify the loop:

```bash
sondera-opencode-adapter health     # {"status":"ok"}
```

## Configuration

All settings can go in `~/.sondera/env`, a per-project `.opencode/sondera.json`, or the process environment. Environment overrides project config.

| Variable | Default | Purpose |
|---|---|---|
| `SONDERA_ENABLED` | `true` | set `false` to disable the plugin |
| `SONDERA_STRICT` | `false` | fail closed: block the tool call on any error or harness unavailability |
| `SONDERA_DRY_RUN` | `false` | evaluate and log denials without blocking |
| `SONDERA_HARNESS_PATH` | (none) | path to `sondera-harness-server`; when set, the plugin auto-starts it |
| `SONDERA_POLICIES_PATH` | (none) | Cedar policy directory, passed to the server as `--policy-path` |
| `SONDERA_SOCKET` | harness default | Unix socket the adapter connects to |
| `SONDERA_ALLOW_PATTERNS` | (none) | comma-separated regexes; matching tool calls skip adjudication |
| `SONDERA_AUDIT_LOG` | (none) | JSONL file recording every adjudication |
| `SONDERA_ADJUDICATE_TIMEOUT_MS` | `5000` | per-call timeout before fail-open |

The harness runs deterministically (Cedar and YARA only) when no LLM provider is configured. To enable the LLM-based classifiers, set `SONDERA_PROVIDER` and credentials in `~/.sondera/env` (see [`docs/configuration.md`](../../docs/configuration.md)); there is no separate "deterministic" flag.

## Modes

- **Strict** (`SONDERA_STRICT=1`): any error, an unreachable harness, or a policy deny blocks the tool call. Use in CI or anywhere enforcement is mandatory.
- **Dry run** (`SONDERA_DRY_RUN=1`): denials are logged but the tool call still runs. Use to measure a policy's impact before enforcing.
- **Default**: fail open. A harness outage or adapter error allows the call; only an explicit `deny` blocks.

## Developing

The plugin is built and tested with [bun](https://bun.sh). From this directory:

```bash
bun install
bun run typecheck
bun test                # unit + stream/oneshot client tests
bun run sync-bundle     # regenerate sondera-bundled.ts (the single-file build opencode loads)
```

The integration test (`src/integration.test.ts`) spawns the real adapter and harness binaries from the repo's `target/debug/`, so build the workspace first (`cargo build --workspace` in the repo root). Point it at a private socket path (avoid `/tmp`, which is world-writable and predictable):

```bash
SONDERA_SOCKET="$(mktemp -d)/sondera.sock" bun test src/integration.test.ts
```

## License

Apache-2.0. The rest of the repository is MIT; this plugin subtree keeps its original Apache-2.0 license (see [LICENSE](LICENSE)).
