# opencode ↔ Sondera adapter protocol

The opencode plugin (`plugins/opencode`) and the Rust adapter (`apps/opencode`, binary `sondera-opencode-adapter`) communicate over stdin/stdout. This document is the contract; both sides must agree on it. Source of truth: `apps/opencode/src/main.rs` and `plugins/opencode/src/types.ts`.

## Commands

The adapter takes one optional command argument:

| Command | Behaviour |
|---|---|
| `health` | Connects to the harness, prints `{"status":"ok"}` and exits 0, or errors on failure. |
| `adjudicate` | Reads one JSON request from stdin, prints one JSON response on stdout. |
| `stream` | Reads NDJSON (one JSON object per line) from stdin, prints one NDJSON response per request, reusing a single harness connection. Default for the plugin. |
| (none) | Defaults to `adjudicate`. |

The adapter fails open: on any local error (harness unreachable, malformed request, IPC failure) it returns `decision: "allow"` with a `reason` rather than crashing or blocking the tool call. The plugin's strict mode is what flips that to fail closed.

## Request

Sent by the plugin, one per tool call:

```json
{
  "trajectory_id": "string",
  "agent_id": "string",
  "tool": "string",
  "action": "string",
  "args": { "...": "..." },
  "cwd": "optional working directory",
  "event_type": "before | after"
}
```

`action` is the normalized Sondera action. The plugin maps opencode tools to these:

| opencode tool | action |
|---|---|
| `bash` | `ShellCommand` (args: `command`) |
| `read` | `FileRead` (args: `path` or `filePath`) |
| `write` | `FileWrite` (args: `path`/`filePath`, `content`) |
| `edit`, `apply_patch` | `FileEdit` (args: `path`/`filePath`, `old_content`/`oldString`, `new_content`/`newString`) |
| `webfetch` | `WebFetch` (args: `url`) |
| other | `ToolCall` (carries `tool` and raw `args`) |

Anything the adapter does not recognise collapses to a generic `ToolCall`, so new opencode tools degrade gracefully instead of breaking.

## Response

Returned by the adapter:

```json
{
  "decision": "allow | deny | escalate",
  "reason": "optional, present on deny or when an error was handled",
  "annotations": [
    { "policy_id": "forbid-rm-rf", "description": "...", "annotations": { "severity": "high" } }
  ]
}
```

`decision` is the only field the plugin acts on: `deny` blocks the tool call (the plugin throws `PolicyDenyError`), `allow` proceeds, `escalate` is recorded. `annotations` come straight from the Cedar policies that decided the request and are surfaced for reporting and the audit log.

## Socket and environment

The adapter connects to the harness on `$SONDERA_SOCKET`, or the harness default socket path. It loads the system then user environment layers (`/etc/sondera/env`, `~/.sondera/env`) on startup so socket and harness configuration in those files is honored.

## Versioning

The protocol is additive. When the request or response shape changes in `apps/opencode/src/main.rs`, update `plugins/opencode/src/types.ts` in the same commit and bump the plugin `version` in `plugins/opencode/package.json` for the npm release.
