# Guardrails

The harness runs three guardrail subsystems over every event before it reaches Cedar. Two are deterministic (YARA signatures and Cedar itself); the IFC and policy classifiers are probabilistic, driven by an LLM. This document covers what each does and how to extend it.

Grounded in `crates/guardrails/signature/`, `crates/guardrails/ifc/src/label.rs`, `crates/guardrails/policy/src/policy.rs`, and the TOML files under `policies/`.

## How they combine

For each Action and Observation event the harness scans the relevant content with all three and packs the results into the Cedar request context:

| Field | Source | Type |
|---|---|---|
| `signature` | YARA-X signature engine | match count, categories, severity 0 to 4 |
| `label` | IFC data-sensitivity classifier | `Public`, `Internal`, `Confidential`, `HighlyConfidential` |
| `policy` | secure-code policy classifier | compliant flag, violation category codes |

A Cedar policy can match on any of the three, so a rule can say "deny shell commands whose output matches the exfiltration signature" or "deny web fetches of confidential content" without caring which subsystem flagged it.

## Signature engine (YARA-X)

The signature engine pattern-matches content against YARA rules compiled once at startup from `crates/guardrails/signature/rules/`. It needs no network and no model. The bundled rule sets are:

| File | Detects |
|---|---|
| `injection.yar` | prompt injection in prompts and tool output |
| `exfil.yar` | exfiltration channels: paste sites, sensitive file access, encoding for transfer |
| `secrets.yar` | API keys, tokens, cloud credentials, private keys |
| `obfuscation.yar` | obfuscated payloads in scripts (base64, hex, eval chains) |
| `pi.yar` | personally identifiable information |

Each rule declares metadata the harness reads into the `SignatureContext`:

```
rule data_exfiltration_sensitive_files {
    meta:
        description = "Detects access to sensitive credential and configuration files"
        severity = "critical"          // none | low | medium | high | critical
        category = "credential_access" // surfaced in context.signature.categories
        mitre_attack = "T1552.001"
    strings:
        $ssh1 = "/.ssh/id_rsa"
        ...
    condition:
        any of them
}
```

`severity` maps to the integer in the context (`0` none through `4` critical); `category` is aggregated across all matched rules into the `categories` set. To add detection, drop a new `.yar` file (or add a rule to an existing one) in `rules/`. The build embeds the directory at compile time with `include_dir!`, so a rebuild is required for new rules to take effect.

## Information flow control (data sensitivity)

The IFC classifier tags content with a sensitivity label so policies can enforce a no-write-down rule: once a trajectory has seen confidential data, it cannot exfiltrate it. Labels follow the Microsoft Purview tiers, ordered `Public < Internal < Confidential < HighlyConfidential`. The model is the highest label among the configured templates for a piece of content, and the harness raises the trajectory's running label to that high-water mark (see `docs/architecture.md`).

The classifier is configured in `policies/ifc.toml`. A label template names the check and lists the categories the model chooses between:

```toml
[[labels]]
name = "DATA_SENSITIVITY"
description = "Data sensitivity classification aligned with Microsoft Purview sensitivity labels."
instructions = """
Evaluate the content for data sensitivity. Classify into one of the categories below.
If the content is sensitive, return: {"sensitive": 1, "sensitivity_category": "<label>"}
If the content is public, return: {"sensitive": 0, "sensitivity_category": "public"}"""

[[labels.categories]]
label = "public"
definition = "Information that can be freely shared externally..."

[[labels.categories]]
label = "highly_confidential"
definition = "Most sensitive data with strict access restrictions..."
```

The category `label` values must match the `Label` enum's serde names (`public`, `internal`, `confidential`, `highly_confidential`). To sharpen detection, edit a category `definition` or add `[[labels.categories]]` entries. To add an entirely separate check (for example a PII-specific label), add another `[[labels]]` block; each is evaluated independently and the maximum is taken.

Examples tune the model. Add `[[labels.examples]]` blocks with `content`, `sensitive` (true/false), and `label` to show the model the boundary cases for your data.

## Secure-code policy

The policy classifier checks generated code and commands against a configurable set of policy templates. Each template names a category prefix and lists severity categories the model selects between, grounded in OWASP Top 10 and CWE. The bundled template in `policies/policies.toml` covers injection, secrets exposure, weak cryptography, deserialization, path traversal, and broken access control.

```toml
[[policies]]
name = "SECURE_CODE_GENERATION"
prefix = "SC"
description = "Security vulnerabilities in AI-generated code based on OWASP Top 10 and CWE."
instructions = """
Evaluate the generated code for security vulnerabilities.
If the content violates this policy, return: {"violation": 1, "policy_category": "<code>"}
If the content is compliant, return: {"violation": 0, "policy_category": "SC0"}"""

[[policies.categories]]
code = "SC0"
name = "Compliant"
definition = "Code follows secure coding practices..."

[[policies.categories]]
code = "SC2"
name = "Injection"
definition = "CWE-78, CWE-89, CWE-79. Unsanitized user input concatenated into..."
```

The category whose code is `{prefix}0` (here `SC0`) is the safe outcome. The model returns a `policy_category` code; when it is not the safe code, the harness records a violation carrying that category. To add a check, append a `[[policies.categories]]` block with a new code and a precise `definition`. Definitions matter more than breadth: a tight, example-backed definition of one CWE produces fewer false positives than a vague one covering many.

Add `[[policies.examples]]` blocks (`content`, `violation`, `category`) to anchor the model on what counts as a violation for your stack. A second independent policy (for example a secrets-in-config check) is another `[[policies]]` block with its own prefix; all are evaluated and any violation is recorded.

## Deterministic versus probabilistic

YARA and Cedar are deterministic: the same input yields the same verdict, with no API dependency. The IFC and policy classifiers depend on the configured LLM provider and are therefore probabilistic, which is why the harness retries transient failures and applies a fail mode when a classifier is unavailable (see `docs/configuration.md`). For the highest-assurance controls, express them as a YARA rule or a Cedar policy; use the LLM classifiers for judgement calls those cannot make, such as "is this code vulnerable" or "is this data confidential".

Both LLM classifiers memoize their results in a bounded in-process LRU keyed by the SHA-256 of the content (1024 entries each). The same command, file, or output classified twice hits the cache and skips the LLM entirely. The cache holds only real LLM results, never the fail-mode substitutes, and resets when the server restarts (when policies or templates change, restart the server).

A circuit breaker wraps each provider client. After five consecutive provider failures (timeouts, network errors, 4xx/5xx, auth) the breaker opens for 30 seconds and subsequent calls return immediately instead of each paying the full retry cost. The next call after the cooldown is a half-open probe that closes the breaker on success or reopens it on failure. Per-content errors (parse failures, refusals, empty output) do not trip the breaker.
