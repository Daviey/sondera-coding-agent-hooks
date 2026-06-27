//! Sondera Harness Server
//!
//! A tarpc-based IPC server that provides policy adjudication services
//! via Unix domain sockets.

use anyhow::Result;
use clap::Parser;
use sondera_harness::{CedarPolicyHarness, rpc};
use std::path::PathBuf;
use tracing_subscriber::fmt::format::FmtSpan;

#[derive(Parser, Debug)]
#[command(name = "sondera-harness-server")]
#[command(about = "Sondera Harness IPC Server")]
#[command(version)]
struct Args {
    /// Path to Unix socket for IPC
    #[arg(short, long)]
    socket: Option<PathBuf>,

    /// Path to Cedar policy directory
    #[arg(short, long, default_value = "policies")]
    policy_path: PathBuf,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging.
    let filter = if args.verbose {
        tracing_subscriber::EnvFilter::new("info,tarpc=warn,sondera=debug")
    } else {
        tracing_subscriber::EnvFilter::new("warn")
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    // Load environment configuration: the system file (`/etc/sondera/env` or `SONDERA_SYSTEM_ENV`)
    // then the user file (`~/.sondera/env`), with organization-enforced precedence. The hook
    // clients load the same layers, but the classifier API calls happen server-side, so the env
    // must be present in this process.
    sondera_config::load();

    let socket_path = args.socket.unwrap_or_else(rpc::default_socket_path);

    tracing::info!("Loading policies from {:?}", args.policy_path);
    let harness = CedarPolicyHarness::from_policy_dir(args.policy_path).await?;

    tracing::info!("Starting harness server on {:?}", socket_path);
    rpc::serve(harness, &socket_path).await?;

    Ok(())
}
