#[tokio::main]
async fn main() -> anyhow::Result<()> {
    phantom_mcp::run_stdio_server().await
}
