pub mod server;
pub(crate) mod tools;

// Re-export param structs needed by integration tests.
pub use tools::params::LeakIncidentsRealtimeParams;

use rmcp::transport::stdio;
use rmcp::ServiceExt;

/// Install a tracing subscriber suitable for MCP stdio servers (logs to stderr,
/// no ANSI, no timestamps). Safe to call when no subscriber has been set yet.
///
/// When embedded inside `phantom mcp serve` the CLI already owns the global
/// subscriber, so we skip re-initialisation — the existing subscriber is fine
/// because it also writes to stderr and leaves stdout clean for JSON-RPC.
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_target(false)
        .try_init();
}

/// Run the Phantom MCP stdio server until the transport closes.
///
/// This is the main entry-point used both by the standalone `phantom-mcp`
/// binary and by `phantom mcp serve` inside the main `phantom` CLI.
pub async fn run_stdio_server() -> anyhow::Result<()> {
    init_tracing();

    tracing::info!("Phantom MCP server starting...");

    let server = server::PhantomMcpServer::new()?;

    let service = server.serve(stdio()).await?;

    service.waiting().await?;

    Ok(())
}
