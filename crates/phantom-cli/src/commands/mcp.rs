use anyhow::Result;
use std::path::Path;

/// External MCP servers use exactly exec's vault/proxy lifecycle. No shell
/// expansion, registry lookup, client-config writes, or secret-valued argv.
pub fn run(name: &str, config: &Path) -> Result<()> {
    let bytes =
        phantom_core::fs::read_regular_file_bounded(config, phantom_mcp::launch::MAX_CONFIG_BYTES)
            .map_err(|_| {
                anyhow::anyhow!(
                    "Cannot read MCP configuration; use a regular file of at most 1 MiB"
                )
            })?
            .ok_or_else(|| anyhow::anyhow!("MCP configuration file does not exist"))?;
    let server = phantom_mcp::launch::parse_server(&bytes, name)?;
    let mut cmd = vec![server.command];
    cmd.extend(server.args);
    super::exec::run_mcp(&cmd, &server.env)
}

pub fn run_serve() -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(phantom_mcp::run_stdio_server())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[test]
    fn mcp_serve_parses() {
        let cli = crate::Cli::try_parse_from(["phantom", "mcp", "serve"]).unwrap();
        assert!(matches!(
            cli.command,
            crate::Commands::Mcp {
                action: crate::McpAction::Serve
            }
        ));
    }

    #[test]
    fn mcp_run_parses_real_cli() {
        let cli = crate::Cli::try_parse_from(["phantom", "mcp", "run", "example"]).unwrap();
        assert!(matches!(cli.command, crate::Commands::Mcp {
            action: crate::McpAction::Run { name, config }
        } if name == "example" && config == std::path::Path::new(".mcp.json")));
    }
}
