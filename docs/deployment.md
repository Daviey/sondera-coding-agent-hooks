# Deployment

Running the harness in production comes down to three things: who owns the Unix socket, where configuration comes from, and what happens when a classifier is unavailable. This document covers each, plus the systemd setup and the trajectory log.

Grounded in `crates/harness/src/rpc.rs`, `crates/harness/src/bin/server.rs`, and `crates/config/`.

## The socket

The hook adapter binaries connect to the harness over a Unix socket. The server picks a default path in this order: `/var/run/sondera/sondera-harness.sock` if it can create `/var/run/sondera`, otherwise `~/.sondera/sondera-harness.sock`. Override either side with `sondera-harness-server --socket /path/to.sock`.

The socket is security-critical: whichever process binds it first adjudicates every hook event for every client. Pre-create the directory with restricted ownership so a rogue process cannot bind the path before the server starts:

```bash
sudo mkdir -p /var/run/sondera
sudo chown sondera:sondera /var/run/sondera
sudo chmod 0750 /var/run/sondera
```

Under systemd, prefer `RuntimeDirectory=sondera` in the unit file. systemd creates `/run/sondera/` with the right ownership automatically and tears it down on stop. Avoid the home-directory fallback in production: its parent is world-writable and vulnerable to a pre-binding race.

## systemd unit

```ini
[Unit]
Description=Sondera Harness Server
After=network.target

[Service]
Type=simple
User=sondera
Group=sondera
RuntimeDirectory=sondera
EnvironmentFile=/etc/sondera/env
ExecStart=/usr/local/bin/sondera-harness-server --socket /run/sondera/sondera-harness.sock -v
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`EnvironmentFile=/etc/sondera/env` loads the organization-managed layer at service start. The server also reads it directly on startup (and layers `~/.sondera/env` on top), so either mechanism works; using both is harmless because the first-set value wins.

## Configuration layers in production

For a multi-user host, pin the security-relevant settings in `/etc/sondera/env` and let users supply their own credentials in `~/.sondera/env`. Because the loader is first-set-wins, a user cannot relax an organization setting (see `docs/configuration.md`). A typical system file:

```
SONDERA_PROVIDER=anthropic
SONDERA_FAIL_MODE=closed-hard
SONDERA_BASE_URL=https://llm-gateway.internal.example.com
```

Users then add their own `ANTHROPIC_API_KEY` (or provider key) in `~/.sondera/env`.

## Failure mode

Pick `SONDERA_FAIL_MODE` for the deployment's risk tolerance:

- `open` tolerates classifier outages at the cost of letting actions through unclassified. Suitable for development or read-heavy workflows.
- `closed` biases to denial through Cedar's normal evaluation when a classifier is unavailable.
- `closed-hard` denies every action outright while a classifier is down, bypassing Cedar. The safest choice for production, at the cost of availability during a provider outage.
- `escalate` returns `Decision::Escalate` for human review while a classifier is down, bypassing Cedar. Use when neither permitting nor denying unclassified actions is acceptable — the hook adapters surface escalations for follow-up.

## Multi-user

One server instance serves all hook clients that can reach the socket. Put users who should share policy and configuration on the same server. Users who need their own policies or provider run a separate server with `--socket` pointed at a path they own, and install their hooks against it.

## Observability

Run the server with `-v` for verbose logging. Per-call classifier events land on the `sondera::llm` tracing target with provider, model, latency in milliseconds, and token counts; signature scans and policy decisions log through the `sondera` target. Every event and every adjudication is also persisted to the trajectory store: a JSONL file under the storage directory and a Turso database. Use these for after-the-fact review of what was allowed and denied.

For a live snapshot, query the stats endpoint from any adapter binary:

```
sondera-opencode-adapter stats
```

Returns event counts (total, allows, denies, errors) and server uptime. Useful for monitoring dashboards or health checks in deployment scripts.

## Graceful shutdown

The server handles SIGINT (Ctrl-C) and SIGTERM, stops accepting new connections, and removes the socket file before exiting. This lets systemd or process managers restart cleanly without orphaned socket files. In-flight requests are not cancelled; the server waits for them to finish.

## Updating policies

Cedar policies, the schema, and the TOML templates are loaded at startup. To change them, edit the files under the policy directory (default `policies/`) and restart the server. There is no hot reload.
