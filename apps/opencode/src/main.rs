//! opencode adapter for the Sondera harness.
//!
//! This is the binary the opencode TypeScript plugin spawns. It normalizes an opencode tool call
//! into a Sondera `Action` event, sends it to the harness server over the Unix socket, and prints
//! the adjudication (`allow` / `deny` / `escalate`) as JSON. Two modes:
//!
//! - `adjudicate` (default): read one JSON request from stdin, print one response.
//! - `stream`: read NDJSON from stdin, print NDJSON responses, reusing one harness connection.
//! - `health`: check the harness server is reachable.
//!
//! The adapter fails open: on any local error (unreachable harness, malformed request, IPC
//! failure) it returns `allow` with a `reason`, so a harness outage never blocks the agent by
//! default. The opencode plugin layer's strict mode is responsible for flipping that to fail
//! closed when desired.
//!
//! Ported from the out-of-tree opencode-sondera plugin (Apache-2.0); MIT here.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sondera_harness::{
    Action, Agent, Annotation, Decision, Event, FileOpType, FileOperation, Harness, HarnessClient,
    ShellCommand, ToolCall, TrajectoryEvent, WebFetch,
};
use std::io::{self, Read, Write};
use tokio::io::AsyncBufReadExt;

#[derive(Deserialize)]
struct AdapterRequest {
    trajectory_id: String,
    agent_id: String,
    tool: String,
    action: String,
    args: serde_json::Value,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    event_type: Option<String>,
}

#[derive(Serialize)]
struct AdapterResponse {
    decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    annotations: Vec<AdapterAnnotation>,
}

#[derive(Serialize)]
struct AdapterAnnotation {
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty", default)]
    annotations: std::collections::HashMap<String, String>,
}

impl From<&Annotation> for AdapterAnnotation {
    fn from(a: &Annotation) -> Self {
        Self {
            policy_id: a.policy_id.clone(),
            description: a.description.clone(),
            annotations: a.annotations.clone(),
        }
    }
}

/// Map an opencode adapter request to a Sondera action. Recognised actions use the typed
/// constructors; anything else collapses to a generic `ToolCall` carrying the raw args.
fn build_action(req: &AdapterRequest) -> Action {
    let call_id = || format!("call-{}", uuid::Uuid::new_v4());
    match req.action.as_str() {
        "ShellCommand" => Action::ShellCommand(ShellCommand {
            call_id: call_id(),
            command: req
                .args
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            working_dir: req.cwd.clone(),
        }),
        "FileRead" => Action::FileOperation(FileOperation {
            call_id: call_id(),
            operation: FileOpType::Read,
            path: req
                .args
                .get("path")
                .or_else(|| req.args.get("filePath"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            content: None,
            old_content: None,
        }),
        "FileWrite" => Action::FileOperation(FileOperation {
            call_id: call_id(),
            operation: FileOpType::Write,
            path: req
                .args
                .get("path")
                .or_else(|| req.args.get("filePath"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            content: req
                .args
                .get("content")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            old_content: None,
        }),
        "FileEdit" => Action::FileOperation(FileOperation {
            call_id: call_id(),
            operation: FileOpType::Edit,
            path: req
                .args
                .get("path")
                .or_else(|| req.args.get("filePath"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            content: req
                .args
                .get("new_content")
                .or_else(|| req.args.get("newString"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            old_content: req
                .args
                .get("old_content")
                .or_else(|| req.args.get("oldString"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        }),
        "WebFetch" => Action::WebFetch(WebFetch {
            call_id: call_id(),
            url: req
                .args
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            prompt: String::new(),
        }),
        _ => Action::ToolCall(ToolCall {
            call_id: call_id(),
            tool: req.tool.clone(),
            arguments: req.args.clone(),
        }),
    }
}

async fn do_adjudicate(client: &HarnessClient, req: AdapterRequest) -> Result<AdapterResponse> {
    let agent = Agent {
        id: req.agent_id.clone(),
        provider_id: "opencode".to_string(),
    };
    let event = Event::new(
        agent,
        &req.trajectory_id,
        TrajectoryEvent::Action(build_action(&req)),
    );
    let result = client.adjudicate(event).await?;
    Ok(AdapterResponse {
        decision: match result.decision {
            Decision::Allow => "allow".to_string(),
            Decision::Deny => "deny".to_string(),
            Decision::Escalate => "escalate".to_string(),
        },
        reason: result.reason,
        annotations: result
            .annotations
            .iter()
            .map(AdapterAnnotation::from)
            .collect(),
    })
}

async fn connect_harness() -> Result<HarnessClient> {
    if let Ok(socket) = std::env::var("SONDERA_SOCKET") {
        return HarnessClient::connect(std::path::Path::new(&socket)).await;
    }
    HarnessClient::connect_default().await
}

async fn adjudicate(req: AdapterRequest) -> Result<AdapterResponse> {
    let client = connect_harness().await?;
    do_adjudicate(&client, req).await
}

async fn stream_mode() -> Result<()> {
    let stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();
    let mut harness_client: Option<HarnessClient> = None;
    let mut stdout = io::BufWriter::new(io::stdout());
    let mut shutting_down = false;

    loop {
        let line = tokio::select! {
            line = lines.next_line() => line?,
            _ = tokio::signal::ctrl_c() => {
                if shutting_down {
                    break;
                }
                eprintln!("[sondera] shutting down, waiting for the current request...");
                shutting_down = true;
                continue;
            }
        };

        let Some(line) = line else { break };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let req: AdapterRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let resp = AdapterResponse {
                    decision: "allow".to_string(),
                    reason: Some(format!("invalid request: {e}")),
                    annotations: vec![],
                };
                writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
                stdout.flush()?;
                continue;
            }
        };

        if harness_client.is_none() {
            match connect_harness().await {
                Ok(c) => harness_client = Some(c),
                Err(e) => {
                    let resp = AdapterResponse {
                        decision: "allow".to_string(),
                        reason: Some(format!("harness unreachable: {e}")),
                        annotations: vec![],
                    };
                    writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
                    stdout.flush()?;
                    continue;
                }
            }
        }

        let Some(client) = harness_client.as_ref() else {
            continue;
        };
        let response = match do_adjudicate(client, req).await {
            Ok(r) => r,
            Err(e) => {
                harness_client = None;
                AdapterResponse {
                    decision: "allow".to_string(),
                    reason: Some(format!("adjudication error: {e}")),
                    annotations: vec![],
                }
            }
        };

        writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
        stdout.flush()?;

        if shutting_down {
            break;
        }
    }

    Ok(())
}

async fn health_check() -> Result<()> {
    let client = connect_harness().await?;
    let healthy = client.health().await?;
    if healthy {
        println!("{}", serde_json::json!({"status": "ok"}));
        Ok(())
    } else {
        anyhow::bail!("harness health check failed")
    }
}

async fn stats_check() -> Result<()> {
    let client = connect_harness().await?;
    let stats = client.stats().await?;
    println!("{}", serde_json::to_string_pretty(&stats)?);
    Ok(())
}

fn print_usage() {
    eprintln!(
        "sondera-opencode-adapter {version}

Usage: sondera-opencode-adapter <command>

Commands:
  health       Check if the harness server is reachable
  stats        Print server statistics (event counts, uptime, allow/deny)
  adjudicate   Read one JSON event from stdin, return adjudication on stdout
  stream       Read NDJSON events from stdin, return NDJSON adjudications

'stream' keeps a persistent connection to the harness server.
With no command, defaults to 'adjudicate'.

Socket: $SONDERA_SOCKET or the harness default
Environment is loaded from /etc/sondera/env then ~/.sondera/env before connecting.",
        version = env!("CARGO_PKG_VERSION")
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load the system then user env layers so SONDERA_SOCKET (and anything else) in the env files
    // is honored. The harness server loads the same layers for its own configuration.
    sondera_config::load();

    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("health") => {
            health_check().await?;
        }
        Some("stats") => {
            stats_check().await?;
        }
        Some("stream") => {
            stream_mode().await?;
        }
        Some("adjudicate") | None => {
            let mut input = String::new();
            io::stdin().read_to_string(&mut input)?;
            let req: AdapterRequest = match serde_json::from_str(input.trim()) {
                Ok(r) => r,
                Err(e) => {
                    let resp = AdapterResponse {
                        decision: "allow".to_string(),
                        reason: Some(format!("invalid request: {e}")),
                        annotations: vec![],
                    };
                    println!("{}", serde_json::to_string(&resp)?);
                    return Ok(());
                }
            };
            let response = match adjudicate(req).await {
                Ok(r) => r,
                Err(e) => AdapterResponse {
                    decision: "allow".to_string(),
                    reason: Some(format!("adjudication error: {e}")),
                    annotations: vec![],
                },
            };
            println!("{}", serde_json::to_string(&response)?);
        }
        Some("--help") | Some("-h") => {
            print_usage();
        }
        Some("--version") | Some("-V") => {
            println!("sondera-opencode-adapter {}", env!("CARGO_PKG_VERSION"));
        }
        Some(cmd) => {
            anyhow::bail!("unknown command: {cmd}. Run with --help for usage.");
        }
    }

    let _ = io::stdout().flush();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_req(action: &str, args: serde_json::Value) -> AdapterRequest {
        AdapterRequest {
            trajectory_id: "test-traj".to_string(),
            agent_id: "test-agent".to_string(),
            tool: "bash".to_string(),
            action: action.to_string(),
            args,
            cwd: Some("/tmp".to_string()),
            event_type: None,
        }
    }

    #[test]
    fn shell_command_extracts_command() {
        let req = make_req(
            "ShellCommand",
            serde_json::json!({"command": "ls -la /tmp"}),
        );
        let action = build_action(&req);
        match action {
            Action::ShellCommand(cmd) => {
                assert_eq!(cmd.command, "ls -la /tmp");
                assert_eq!(cmd.working_dir.as_deref(), Some("/tmp"));
                assert!(cmd.call_id.starts_with("call-"));
            }
            _ => panic!("expected ShellCommand, got {action:?}"),
        }
    }

    #[test]
    fn file_read_extracts_path() {
        let req = make_req("FileRead", serde_json::json!({"path": "/etc/hosts"}));
        let action = build_action(&req);
        match action {
            Action::FileOperation(fo) => {
                assert_eq!(fo.path, "/etc/hosts");
                assert_eq!(fo.operation, FileOpType::Read);
                assert!(fo.content.is_none());
            }
            _ => panic!("expected FileOperation, got {action:?}"),
        }
    }

    #[test]
    fn file_read_supports_file_path_alias() {
        let req = make_req("FileRead", serde_json::json!({"filePath": "/etc/hosts"}));
        let action = build_action(&req);
        match action {
            Action::FileOperation(fo) => assert_eq!(fo.path, "/etc/hosts"),
            _ => panic!("expected FileOperation"),
        }
    }

    #[test]
    fn file_write_extracts_content() {
        let req = make_req(
            "FileWrite",
            serde_json::json!({"path": "/tmp/test.txt", "content": "hello"}),
        );
        let action = build_action(&req);
        match action {
            Action::FileOperation(fo) => {
                assert_eq!(fo.operation, FileOpType::Write);
                assert_eq!(fo.path, "/tmp/test.txt");
                assert_eq!(fo.content.as_deref(), Some("hello"));
            }
            _ => panic!("expected FileOperation, got {action:?}"),
        }
    }

    #[test]
    fn file_edit_extracts_old_and_new() {
        let req = make_req(
            "FileEdit",
            serde_json::json!({"path": "/tmp/test.txt", "oldString": "old", "newString": "new"}),
        );
        let action = build_action(&req);
        match action {
            Action::FileOperation(fo) => {
                assert_eq!(fo.operation, FileOpType::Edit);
                assert_eq!(fo.old_content.as_deref(), Some("old"));
                assert_eq!(fo.content.as_deref(), Some("new"));
            }
            _ => panic!("expected FileOperation, got {action:?}"),
        }
    }

    #[test]
    fn file_edit_supports_alternate_field_names() {
        let req = make_req(
            "FileEdit",
            serde_json::json!({"filePath": "/tmp/test.txt", "old_content": "old", "new_content": "new"}),
        );
        let action = build_action(&req);
        match action {
            Action::FileOperation(fo) => {
                assert_eq!(fo.path, "/tmp/test.txt");
                assert_eq!(fo.old_content.as_deref(), Some("old"));
                assert_eq!(fo.content.as_deref(), Some("new"));
            }
            _ => panic!("expected FileOperation, got {action:?}"),
        }
    }

    #[test]
    fn web_fetch_extracts_url() {
        let req = make_req(
            "WebFetch",
            serde_json::json!({"url": "https://example.com"}),
        );
        let action = build_action(&req);
        match action {
            Action::WebFetch(wf) => assert_eq!(wf.url, "https://example.com"),
            _ => panic!("expected WebFetch, got {action:?}"),
        }
    }

    #[test]
    fn unknown_action_falls_back_to_tool_call() {
        let req = make_req("CustomAction", serde_json::json!({"foo": "bar"}));
        let action = build_action(&req);
        match action {
            Action::ToolCall(tc) => {
                assert_eq!(tc.tool, "bash");
                assert_eq!(tc.arguments["foo"], "bar");
            }
            _ => panic!("expected ToolCall, got {action:?}"),
        }
    }

    #[test]
    fn empty_command_defaults_to_empty_string() {
        let req = make_req("ShellCommand", serde_json::json!({}));
        let action = build_action(&req);
        match action {
            Action::ShellCommand(cmd) => assert_eq!(cmd.command, ""),
            _ => panic!("expected ShellCommand, got {action:?}"),
        }
    }
}
