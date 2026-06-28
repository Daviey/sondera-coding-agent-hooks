# Architecture

This document describes how a single agent action becomes an Allow or Deny decision, and the data model the harness builds along the way. It is grounded in `crates/harness/src/cedar/mod.rs`, `crates/harness/src/cedar/transform.rs`, `crates/harness/src/types.rs`, and `policies/base.cedarschema`.

## Request flow

```
agent (Claude/Cursor/Copilot/Gemini)
   │  tool call, as agent-specific JSON on stdin
   ▼
hook adapter binary  (apps/<agent>)
   │  reads stdin JSON, connects to the Unix socket
   ▼
harness server  (sondera-harness-server)
   │  normalizes to a trajectory Event, then:
   │    1. YARA signature scan        (sondera-signature)
   │    2. IFC data-sensitivity tag   (sondera-information-flow-control)
   │    3. secure-code policy eval     (sondera-policy)
   │  builds a Cedar request and authorizes it
   ▼
Cedar policy engine
   │  Allow or Deny, with policy annotations
   ▼
hook adapter
   │  translates the decision back into the agent's response shape on stdout
   ▼
agent proceeds, or is blocked
```

The agent never talks to Cedar or to the LLM classifiers directly. The hook adapter is a thin stdin/stdout translator; the harness server holds the policy engine, the entity store, the trajectory store, and the classifier clients.

## Trajectories and events

The harness models a session as a **trajectory**: an ordered sequence of events attributed to one agent. Every event is an `Event` envelope (`types.rs`) carrying an id, a trajectory id, the agent, a timestamp, an actor, a causation chain, and a payload. The payload is one of four categories (`TrajectoryEvent`):

| Category | When | Examples |
|---|---|---|
| Action | before the agent does something | `ShellCommand`, `FileOperation` (read/write/edit/delete), `WebFetch`, `ToolCall` |
| Observation | the environment's response, after | `ShellCommandOutput`, `FileOperationResult`, `WebFetchOutput`, `ToolOutput`, `Prompt` |
| Control | lifecycle, not authorized | `Started`, `Completed`, `Failed`, `Adjudicated`, `Terminated`, `Suspended`, `Resumed` |
| State | environment snapshot | `Snapshot` (cwd, open files, git branch) |

Each agent adapter normalizes its own JSON into these common types. Claude's `Bash`, Cursor's shell hook, Copilot's `bash`, and Gemini's `bash` all become the same `Action::ShellCommand`, so a policy written once applies to all of them. Control events (session start, completion) are recorded but never denied; only Action and Observation events reach the policy engine.

## Adjudication pipeline

For every Action and Observation event, `adjudicate` runs the pipeline below. Actions (pre-execution gates) run the full pipeline including the LLM classifiers. Observations (post-execution analysis) skip the LLM classifiers (steps 3-4) and use the trajectory's existing label, keeping the deterministic YARA scan and Cedar evaluation — unless a YARA signature match meets the `SONDERA_LLM_YARA_SEVERITY` threshold (default: any match), which overrides the skip. The set of Action types that get the LLM can also be narrowed with `SONDERA_LLM_EVENT_TYPES` (see `docs/configuration.md`).

1. **Persist the event** to the JSONL file store and the Turso trajectory store.
2. **Scan** the relevant content (command, file path and contents, URL and prompt, tool output) with YARA signatures. This is deterministic and produces a `SignatureContext`: match count, threat categories, and a severity from 0 (none) to 4 (critical).
3. **Classify sensitivity** with the IFC model, producing a `Label` (`Public`, `Internal`, `Confidential`, `HighlyConfidential`).
4. **Evaluate** the content against the secure-code policy templates, producing a `PolicyContext` (compliant flag and violation categories).
5. **Build a Cedar request**: principal is the `Agent`, resource is the `Trajectory` (or a `Message`/`File` for prompt and file actions), and the context carries the signature, label, policy, and workspace fields.
6. **Authorize** with the loaded Cedar policy set.
7. **Record an `Adjudicated` Control event** on the same trajectory and return the decision.

The IFC and policy classifier calls are independent of each other, so the harness runs them concurrently (bounded) rather than sequentially. How a classifier failure is handled is set by `SONDERA_FAIL_MODE` (see `docs/configuration.md`): substitute benign defaults, substitute restrictive defaults, or deny outright.

## Entities

Cedar authorizes requests against an entity graph. The schema (`policies/base.cedarschema`) defines:

- `Agent` and `User` as principals. `Agent` carries a `provider_id` (`claude`, `cursor`, etc.).
- `Trajectory` as the resource for shell, web, and result actions. It tracks `step_count`, the running sensitivity `label`, and accumulated `taints`.
- `Message` (a prompt) as a child of `Trajectory`, with `content` and `role`.
- `File` as the resource for file operations, with a sensitivity `label`.
- `Label` and `Taint` as memberless entities used for information-flow reasoning, and `Role` for message roles.

### The label lattice

`Label` is ordered `Public < Internal < Confidential < HighlyConfidential`. The four `Label` entities are inserted into the entity store with that parent chain (`HighlyConfidential` is a child of `Confidential`, and so on down to `Public`), so a policy can write hierarchical matches with `in`, for example `resource.label in Label::"Confidential"` to cover Confidential and everything more sensitive. The bundled `ifc.cedar` policies currently match exact tiers with `==` and write a separate rule for each, so the parent chain is available but not yet relied upon.

### High-water-mark propagation

When an event carries content at a given sensitivity, the harness raises the trajectory's label to the higher of its current value and the new content's label (`transform.rs`). Reading a `HighlyConfidential` file therefore taints the whole trajectory: every subsequent action on that trajectory is evaluated with a `HighlyConfidential` label, so a later exfiltration attempt is denied even if the exfiltrating command itself looks benign. File reads also set the `File` entity's label, which then propagates to the trajectory.

## Actions and their context

Each action has a typed context the policies match on:

| Action | Resource | Pre or post | Notable context fields |
|---|---|---|---|
| `Prompt` | `Message` | post | signature, label |
| `ShellCommand` | `Trajectory` | pre | command, working_dir, signature, policy, label |
| `ShellCommandOutput` | `Trajectory` | post | command, exit_code, stdout, stderr, signature, policy, label |
| `WebFetch` | `Trajectory` | pre | url, prompt, signature, policy, label |
| `WebFetchOutput` | `Trajectory` | post | url, code, result, signature, policy, label |
| `FileRead`/`FileWrite`/`FileEdit`/`FileDelete` | `File` | pre | path, operation, signature, policy, label |
| `FileOperationResult` | `Trajectory` | post | path, content, signature, policy, label |
| `ToolOutput` | `Trajectory` | post | content, signature, policy, label |

Pre-execution actions are where a `forbid` prevents the operation from running (the command is never executed, the fetch never sent). Post-execution actions evaluate observed output; a deny there is recorded and can flag a violation after the fact, and it raises the trajectory label for future events.

## Decision

Cedar returns `Allow` or `Deny`. The harness maps that to an `Adjudicated` record carrying the decision, the policy annotations that drove it (policy id, description, and any custom annotations such as severity or rule codes the policy declares), and a reason assembled from any Cedar diagnostics errors. That record becomes an `Adjudicated` Control event on the trajectory and the value returned to the hook adapter, which translates Allow/Deny back into the agent-specific response on stdout.

A single matching `forbid` overrides any number of `permit` policies, so the policy set is default-permit with targeted prohibitions. Adding a `.cedar` file to the policy directory extends the set; the harness loads every `.cedar` and `.cedarschema` file at startup (see `docs/policies.md`).
