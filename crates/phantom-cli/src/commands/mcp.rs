use anyhow::Result;

pub fn run_serve() -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(phantom_mcp::run_stdio_server())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    /// Minimal harness: just enough of the CLI to verify `phantom mcp serve` parses cleanly.
    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        command: TestCommands,
    }

    #[derive(clap::Subcommand)]
    enum TestCommands {
        Mcp {
            #[command(subcommand)]
            action: McpAction,
        },
    }

    #[derive(clap::Subcommand)]
    enum McpAction {
        Serve,
    }

    #[test]
    fn mcp_serve_parses() {
        let cli = TestCli::try_parse_from(["phantom", "mcp", "serve"]).unwrap();
        assert!(matches!(
            cli.command,
            TestCommands::Mcp {
                action: McpAction::Serve
            }
        ));
    }
}
