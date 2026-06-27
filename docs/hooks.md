# Hooks

Each supported agent (Claude Code, Cursor, GitHub Copilot, Gemini CLI) has a small adapter binary that sits between the agent and the harness. The agent calls the binary as a shell command on lifecycle events, passing JSON on stdin; the binary forwards a normalized event to the harness over the Unix socket, gets back an Allow or Deny, and writes the agent-specific response on stdout.

Grounded in `apps/<agent>/src/app/{install,hooks,types,response}.rs` and `crates/common/src/lib.rs`.

## Installing

Each adapter has `install` and `uninstall` subcommands that write a `hooks` block into the agent's settings JSON. Choose a scope:

| Scope | Flag | File | Use |
|---|---|---|---|
| Local (default) | (none) | `.claude/settings.local.json` | per-project, not committed |
| Project | `--project` | `.claude/settings.json` | per-project, committed, shared with the team |
| User | `--user` | `~/.claude/settings.json` | every project for this user |

```bash
cargo run -p sondera-claude -- install            # local
cargo run -p sondera-claude -- install --project  # shared with the repo
cargo run -p sondera-claude -- install --user     # all your projects
cargo run -p sondera-claude -- uninstall --user   # remove, same scope
```

Cursor, Copilot, and Gemini follow the same pattern (`sondera-cursor`, `sondera-copilot`, `sondera-gemini`), each writing to its own settings location. The installer backs up the existing settings file before writing, so uninstall or rollback is straightforward.

### opencode

opencode differs from the others: its plugin system is JavaScript, so the opencode integration is split. The Rust adapter lives in-tree at `apps/opencode` (binary `sondera-opencode-adapter`); the TypeScript plugin opencode loads lives alongside it at `plugins/opencode` (published to npm as `opencode-sondera`). The plugin spawns the adapter as a subprocess and talks to it over stdin/stdout (one JSON per request in `adjudicate` mode, or NDJSON in `stream` mode). The adapter normalizes opencode tool calls to the same Sondera actions and connects to the harness socket (`SONDERA_SOCKET`, or the default). It fails open by default; the plugin's strict mode flips that. The wire contract between the two is documented in `plugins/opencode/PROTOCOL.md`; install and configuration are in `plugins/opencode/README.md`.

The installer finds the binary on `PATH`, then falls back to `~/.cargo/bin`, `/usr/local/bin`, and `/usr/bin`. Install the binary first (`cargo install --path apps/claude`, or your package manager) so the installer can locate it.

## The lifecycle events

The installer registers every lifecycle event the agent emits. For Claude Code these are `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PostToolUseFailure`, `UserPromptSubmit`, `Notification`, `Stop`, `SubagentStart`, `SubagentStop`, `TeammateIdle`, `TaskCompleted`, `PreCompact`, `SessionStart`, and `SessionEnd`. Each is wired to a command of the form:

```
/usr/local/bin/sondera-claude --verbose pre-tool-use
```

The event name is passed as the sole argument; the event payload arrives on stdin. The other adapters register their own event names, but the contract is identical: stdin JSON in, stdout response out, exit code and JSON fields signalling the decision.

## What each event becomes

The adapter normalizes the agent's JSON into a trajectory `Event` (see `docs/architecture.md`) before sending it to the harness:

| Agent event | Becomes |
|---|---|
| `SessionStart` | `Control::Started` (creates the trajectory) |
| `SessionEnd` | `Control::Completed` or `Failed` |
| `PreToolUse` (Bash/shell) | `Action::ShellCommand` (evaluated before execution; a Deny stops it) |
| `PreToolUse` (Read/Write/Edit) | `Action::FileOperation` (pre-execution; Deny blocks it) |
| `PreToolUse` (WebFetch) | `Action::WebFetch` (pre-execution; Deny blocks it) |
| `PostToolUse` | the matching `Observation` (`ShellCommandOutput`, `FileOperationResult`, `WebFetchOutput`, `ToolOutput`) |
| `UserPromptSubmit` | `Observation::Prompt` |
| other lifecycle events | recorded as `Control` or `State`, not authorized |

Pre-execution events are where a Deny actually prevents the action: the command never runs, the file is never written, the fetch never sent. Post-execution events evaluate what came back; a Deny there is recorded on the trajectory and raises the sensitivity label for subsequent events, which can block later exfiltration.

## Runtime contract

The adapter reads one JSON object from stdin, loads the system and user environment layers (see `docs/configuration.md`), connects to the harness on its default Unix socket, sends the event, and prints a `HookResponse` on stdout. The response carries the Allow/Deny decision in the shape the agent expects: for Claude, a JSON object with a `decision` field and an optional reason; for others, the equivalent fields or a non-zero exit code.

The harness server must be running and reachable on the socket. If the adapter cannot connect, it errors on stderr and the agent's own hook-failure behaviour applies (most agents treat a hook error as non-blocking by default). Start the server before launching the agent:

```bash
sondera-harness-server -v
```

## Verifying

Run the adapter by hand to see the stdin/stdout contract and the decision. Pipe a representative payload and the event name:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' | sondera-claude --verbose pre-tool-use
```

With `-v`, the adapter and the server both log to stderr, including the `sondera::llm` events with provider, model, latency, and token counts (see `docs/configuration.md`).
