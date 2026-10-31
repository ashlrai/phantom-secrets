use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum McpAction {
    /// Run the MCP stdio server in-process (used by AI clients like Claude Code)
    Serve,
}
