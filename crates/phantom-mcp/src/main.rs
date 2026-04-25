mod server;
mod tools;

use rmcp::transport::stdio;
use rmcp::ServiceExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // MCP servers MUST log to stderr, never stdout (stdout is the JSON-RPC transport)
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_target(false)
        .init();

    tracing::info!("Phantom MCP server starting...");

    let server = server::PhantomMcpServer::new()?;

    let service = server.serve(stdio()).await?;

    service.waiting().await?;

    Ok(())
}
