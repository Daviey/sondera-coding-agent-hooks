# Configuration

The harness reads its runtime configuration from environment variables. These come from two files, loaded in order:

1. the system file at `/etc/sondera/env` (overridable with `SONDERA_SYSTEM_ENV`), owned by the organization;
2. the user file at `~/.sondera/env`, owned by the user.

Both the hook clients and the harness server load these layers at startup, so the classifier calls (which run inside the server process) see the same settings as the agent adapters.

Precedence is first-set-wins: a variable already set in the process environment, or in an earlier file, is never overwritten. The effective order is process environment, then system file, then user file. An organization can pin security-relevant settings (`SONDERA_PROVIDER`, `SONDERA_FAIL_MODE`, `SONDERA_BASE_URL`) and a user cannot relax them, while still supplying their own values for anything left unset, such as a personal API key.

```bash
# system file (organization-managed)
sudo mkdir -p /etc/sondera
sudo tee /etc/sondera/env >/dev/null <<'EOF'
SONDERA_PROVIDER=anthropic
SONDERA_FAIL_MODE=closed-hard
EOF
sudo chmod 644 /etc/sondera/env

# user file (personal credentials)
mkdir -p ~/.sondera
cat > ~/.sondera/env <<'EOF'
ANTHROPIC_API_KEY=sk-ant-...
EOF
chmod 600 ~/.sondera/env
```

Any variable can also be exported directly in the shell that launches the server, which beats both files.

## Provider and model

Selects which LLM serves the data-sensitivity (IFC) and secure-code (policy) classifiers.

| Variable | Values | Default |
|---|---|---|
| `SONDERA_PROVIDER` | `anthropic`, `openai`, `ollama`, `vertex`, `zai` | `anthropic` |
| `SONDERA_MODEL` | model id | per-provider default (see below) |
| `SONDERA_TEMPERATURE` | sampling temperature, float | `0.0` |
| `SONDERA_BASE_URL` | override the provider's base URL (proxies, gateways, self-hosted) | the provider's standard endpoint |
| `SONDERA_SYSTEM_ENV` | path to the system env file | `/etc/sondera/env` |
| `SONDERA_REASONING_CONTROL` | JSON object merged into the request body to control reasoning/thinking | unset (no reasoning control) |

Default model per provider: `claude-haiku-4-5` (anthropic), `gpt-4o-mini` (openai), `gpt-oss-safeguard:20b` (ollama), `gemini-2.0-flash` (vertex), `glm-4.6` (zai).

Reasoning models (such as `gpt-oss-safeguard-20b`) produce a chain-of-thought before each answer, adding 1 to 5 seconds per classification. For lower latency, choose a non-reasoning model (Haiku, Flash, `gpt-4o-mini`). The classifiers run concurrently, so the per-call latency is the slower of IFC and policy. Repeat content is served from the LRU cache (no LLM call).

## When the LLM classifiers run

By default, the LLM classifiers run on every **Action** event (pre-execution gates: shell commands, file writes, web fetches) and skip **Observation** events (post-execution: command output, file contents, prompts) for latency. Two settings refine this. For the full decision tree (caching, circuit breaker, retry, fail mode), see [`llm-engagement.md`](llm-engagement.md).

### Event-type filter

`SONDERA_LLM_EVENT_TYPES` narrows which event types get the LLM. Comma-separated, case-insensitive, matching Cedar action identifiers:

| Value | Effect |
|---|---|
| unset (default) | All Action events get the LLM |
| `ShellCommand,WebFetch,FileWrite,FileEdit` | Only those types get the LLM; `FileRead`, `FileDelete`, `ToolCall`, and all Observations skip |

Useful for trimming LLM cost on low-risk action types like `FileRead` without losing coverage on write/execute operations.

Valid type names: `ShellCommand`, `WebFetch`, `FileRead`, `FileWrite`, `FileEdit`, `FileDelete`, `PreToolUse`, `Prompt`, `ShellCommandOutput`, `WebFetchOutput`, `FileOperationResult`, `ToolOutput`.

### YARA trigger

`SONDERA_LLM_YARA_SEVERITY` overrides the event-type filter when a YARA signature match is found. If the scan of the event's primary content meets the threshold, the LLM classifiers run regardless:

| Value | Effect |
|---|---|
| `low` (default) | Any YARA match (severity ≥ 1) triggers the LLM |
| `medium` | Medium+ matches only |
| `high` | High+ matches only |
| `critical` | Critical only |
| `off` / `none` / `0` | Disable the YARA trigger (never override the filter) |

This is how secrets or injection patterns in command **output** (an Observation that would normally skip the LLM) still reach the IFC classifier: YARA detects the pattern, and the threshold override forces the LLM to classify it.

## Per-classifier model

IFC and policy normally share `SONDERA_MODEL`. Override each independently so one classifier can run a cheaper model than the other:

| Variable | Applies to |
|---|---|
| `SONDERA_IFC_MODEL` | the IFC data-sensitivity classifier |
| `SONDERA_POLICY_MODEL` | the secure-code policy classifier |

Both fall back to `SONDERA_MODEL` when unset. Provider, credentials, and base URL stay shared.

## Reasoning control

Reasoning models (z.ai GLM-4.6+, Vertex gpt-oss-safeguard) generate a chain-of-thought before answering, adding latency and tokens the classifiers don't need. `SONDERA_REASONING_CONTROL` accepts a JSON object that's merged into the request body to reduce or disable reasoning.

Recommended values per model:

| Model | Value | Effect |
|---|---|---|
| z.ai GLM-4.5+/4.6/5.x | `{"thinking":{"type":"disabled"}}` | Disables chain-of-thought entirely |
| Vertex gpt-oss-safeguard (deployed) | `{"reasoning_effort":"low"}` | Minimal reasoning (Harmony rejects "none") |
| Non-reasoning (Flash, Haiku, Mini) | unset | No effect needed |

For Vertex, the field is only sent to deployed vLLM endpoints (when `VERTEX_ENDPOINT_ID` is set), not to the first-party Gemini shim.

```bash
# z.ai GLM models
SONDERA_REASONING_CONTROL='{"thinking":{"type":"disabled"}}'

# Vertex deployed endpoint
SONDERA_REASONING_CONTROL='{"reasoning_effort":"low"}'
```

## Credentials

One key per hosted provider. Ollama needs none.

| Variable | Required when |
|---|---|
| `ANTHROPIC_API_KEY` | `SONDERA_PROVIDER=anthropic` |
| `OPENAI_API_KEY` | `SONDERA_PROVIDER=openai` |
| `ZAI_API_KEY` | `SONDERA_PROVIDER=zai` |

## Vertex AI

Vertex authenticates with Application Default Credentials, not a static key. `gcloud auth application-default login` (or a service-account key file pointed at by `GOOGLE_APPLICATION_CREDENTIALS`) provides the token.

| Variable | Purpose | Default |
|---|---|---|
| `VERTEX_PROJECT` | GCP project id (required) | |
| `VERTEX_LOCATION` | GCP region | `us-central1` |
| `VERTEX_ENDPOINT_ID` | numeric id of a deployed Model Garden endpoint (vLLM). Requests go to that endpoint's `:rawPredict` path on its dedicated hostname. | |
| `VERTEX_PROJECT_NUMBER` | numeric project number, needed for the dedicated hostname | resolved from `VERTEX_PROJECT` via the Cloud Resource Manager API |

When `VERTEX_ENDPOINT_ID` is set, the harness targets a deployed vLLM endpoint (for example an open model like `gpt-oss-safeguard-20b`) through the dedicated prediction hostname. When it is unset, it targets the first-party OpenAI-compatible shim (`/endpoints/openapi/chat/completions`) for Gemini and partner models. Both paths accept the structured-output request the client sends.

## Classifier failure mode

The LLM classifiers can fail or be unreachable. `SONDERA_FAIL_MODE` decides what the harness does then.

| Value | Behaviour on classifier failure |
|---|---|
| `open` (default) | Substitutes benign defaults (Public label, compliant policy) so Cedar permits the action. This matches the original non-blocking behaviour. |
| `closed` | Substitutes restrictive defaults (Highly Confidential label, a `FAIL_CLOSED` violation) so Cedar's forbids deny the action. |
| `closed-hard` | Denies the action outright, bypassing Cedar. Use when an unavailable classifier must never let any action through. |
| `escalate` | Returns `Decision::Escalate` for human review, bypassing Cedar. A middle ground between `open` and `closed-hard`: while a classifier is down, actions are neither auto-permitted nor auto-denied. The hook adapters record the escalation for follow-up. |

`closed` is biased toward denial through Cedar's normal evaluation. `closed-hard` is a guaranteed deny regardless of the action. `escalate` surfaces the action for review instead of deciding automatically.

## Logging

The server and the hook binaries take `-v` (verbose). Verbose mode sets the filter to `sondera=debug`, which surfaces the per-call observability events the LLM client emits to the `sondera::llm` tracing target: provider, model, latency in milliseconds, and prompt, completion, and total token counts on success, or the error on failure. Without `-v` the filter is `warn`, so only failures and warnings appear.

For a quick snapshot without verbose logs, use the stats subcommand from any adapter binary:

```
sondera-opencode-adapter stats
```

This prints event counts (total, allows, denies, escalations, errors) and server uptime as JSON.

## Harness server command line

`sondera-harness-server`:

| Flag | Default | Purpose |
|---|---|---|
| `-s, --socket <PATH>` | `/var/run/sondera/sondera-harness.sock` if writable, else `~/.sondera/sondera-harness.sock` | Unix socket for hook clients |
| `-p, --policy-path <DIR>` | `policies` | directory of `.cedar` and `.cedarschema` files |
| `-v, --verbose` | off | verbose logging |

## `policy-eval` command line

The standalone evaluator (`crates/guardrails/policy/src/bin/policy_eval.rs`):

| Flag | Default | Purpose |
|---|---|---|
| `<INPUT>` (positional) | required | file whose contents to evaluate |
| `-p, --policies <PATH>` | `policies/policies.toml` | policy templates file |
| `--provider <...>` | `anthropic` | same value set as `SONDERA_PROVIDER` |
| `--base-url <URL>` | provider default | override base URL |
| `--model <ID>` | provider default | model id |
| `--json` | off | print raw JSON instead of the report |

Exit code is `0` when the content is compliant, `1` when a violation is found.

## Policy files

These live under the policy directory (default `policies/`) and are not environment configuration:

| File | Contents |
|---|---|
| `*.cedarschema` | Cedar entity types and actions |
| `*.cedar` | Cedar policies (baseline, destructive, file, IFC, supply-chain) |
| `ifc.toml` | sensitivity label templates for the data classifier |
| `policies.toml` | secure-code policy templates for the policy classifier |

## Example configurations

Anthropic:

```
SONDERA_PROVIDER=anthropic
SONDERA_MODEL=claude-haiku-4-5
ANTHROPIC_API_KEY=sk-ant-...
```

OpenAI with a split model setup (cheap data tagging, stronger code review):

```
SONDERA_PROVIDER=openai
SONDERA_MODEL=gpt-4o-mini
SONDERA_IFC_MODEL=gpt-4o-mini
SONDERA_POLICY_MODEL=gpt-4o
OPENAI_API_KEY=sk-...
```

Local Ollama:

```
SONDERA_PROVIDER=ollama
SONDERA_MODEL=gpt-oss-safeguard:20b
```

z.ai:

```
SONDERA_PROVIDER=zai
SONDERA_MODEL=glm-4.6
ZAI_API_KEY=...
```

Vertex deployed endpoint (Model Garden vLLM), with fail-closed-hard:

```
SONDERA_PROVIDER=vertex
SONDERA_MODEL=<model id served by the endpoint>
VERTEX_PROJECT=my-project
VERTEX_LOCATION=europe-west2
VERTEX_ENDPOINT_ID=<numeric deployed-endpoint id>
VERTEX_PROJECT_NUMBER=<numeric project number>
SONDERA_FAIL_MODE=closed-hard
```

Vertex first-party shim (Gemini and partner models, no deployed endpoint):

```
SONDERA_PROVIDER=vertex
SONDERA_MODEL=gemini-2.5-flash
VERTEX_PROJECT=my-project
VERTEX_LOCATION=europe-west2
```
