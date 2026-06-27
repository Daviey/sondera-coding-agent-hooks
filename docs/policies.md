# Policies (Cedar)

Cedar is the deterministic decision layer. The harness loads every `.cedar` and `.cedarschema` file from the policy directory (default `policies/`) at startup, evaluates the full policy set on each event, and returns Allow or Deny. A single matching `forbid` overrides any number of `permit` policies, so the style is default-permit with targeted prohibitions.

Grounded in `policies/` and `crates/harness/src/cedar/mod.rs`.

## How a request is built

Cedar authorizes a `(principal, action, resource, context)` tuple. For Sondera the principal is the `Agent` (or `User`), the action is one of the lifecycle actions, the resource is the `Trajectory` (or a `Message` or `File`), and the context carries the guardrail outputs. The full set of entities, context types, and actions is defined in `policies/base.cedarschema`; see `docs/architecture.md` for the action table. Policies match on the action and read fields from `context` and `resource`.

## The bundled policy files

| File | Purpose |
|---|---|
| `base.cedar` | default-permit baseline; targeted forbids for prompt injection, credential access, exfiltration, and shell/web/file pre- and post-execution gates; trajectory runaway protection |
| `destructive.cedar` | irreversible operations: `rm -rf`, git force-push and hard reset, `terraform destroy`, `DROP DATABASE`, lockfile deletion, `kill -9` |
| `file.cedar` | file-type-aware guards: Bell-LaPadula no-write-down, private-key access, secrets in source, obfuscation in scripts, OWASP/CWE policy violations |
| `ifc.cedar` | information flow control: sensitivity-gated outbound blocking, taint propagation, network tool restrictions, step-count limits scaled by classification |
| `supply_chain_risk.cedar` | typosquatting, dependency confusion, build-script injection, lockfile tampering, registry exfiltration |

Drop a new `.cedar` file in the directory and restart the server to extend the set. The harness expects exactly one `.cedarschema` and any number of `.cedar` files.

## Writing a policy

A policy is `forbid` or `permit`, scoped to an action, with a `when` clause over `principal`, `resource`, and `context`. Annotations carry the id and a description the harness surfaces in the decision record.

A targeted forbid (block recursive delete):

```cedar
@id("forbid-rm-rf")
@description("Block recursive force-delete commands (rm -rf).")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*rm -rf *"
};
```

A guard that combines a deterministic signal with a classifier output (block web fetches when the trajectory is confidential and a signature matched):

```cedar
@id("ifc-forbid-webfetch-confidential-with-signatures")
@description("Block web fetches on confidential trajectories when YARA signatures matched.")
forbid (
    principal,
    action == Action::"WebFetch",
    resource
) when {
    resource.label == Label::"Confidential" &&
    context.signature.matches > 0
};
```

A guard using accumulated taint (block outbound once the trajectory has shown exfiltration intent):

```cedar
forbid (
    principal,
    action == Action::"WebFetch",
    resource
) when {
    resource.taints.contains(Taint::"exfiltration")
};
```

### Fields available to match on

From `context` (per action, see the schema): `workspace.cwd`, `workspace.permission_mode`, `signature.matches`, `signature.categories`, `signature.severity`, `policy.compliant`, `policy.violations`, `label`, and the action-specific fields such as `command`, `url`, `path`, `stdout`, `exit_code`. From `resource`: a `Trajectory` exposes `step_count`, `label`, and `taints`; a `File` exposes `label`; a `Message` exposes `content` and `role`.

### Annotations

`@id` sets the policy identifier the harness records (without it, the policy's generated id is used). `@description` becomes the human-readable reason. Any other annotation key is preserved and surfaced in the decision's annotations, so you can tag policies with metadata such as `@severity("high")` or `@owner("platform-security")` and read it downstream.

## Decision

Cedar returns `Allow` or `Deny`. The harness maps that to an `Adjudicated` record with the decision, the annotations of the policies that drove it, and any Cedar diagnostics as the reason. That record is written to the trajectory and returned to the hook adapter. There is no built-in Escalate decision in the Cedar path; escalation is expressed by writing a policy and handling the Deny in the agent workflow, or by extending the harness.

## Authoring with the MCP server

`crates/mcp` exposes an MCP server for interactive Cedar policy authoring and validation against the loaded schema. A policy agent can draft a `.cedar` rule, check it compiles against `base.cedarschema`, test it against sample entities, and write it into the policy directory. This keeps policy authoring grounded in the real schema rather than free-form text.

## Verifying

Load errors surface at startup: the harness fails fast if the schema does not parse, if a policy references an unknown action or context field, or if two policies share an id. Run `cargo test -p sondera-harness` for the policy-loading tests, and exercise a live trajectory with the `--ignored` integration tests under `crates/harness/tests/`.
