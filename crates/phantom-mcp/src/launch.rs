//! Value-blind configuration for launching an external stdio MCP server.
//!
//! This module never opens a vault or starts a process. The CLI applies the
//! protected exec policy after parsing; no config string is a secret resolver.
use anyhow::{bail, Result};
use serde::Deserialize;
use std::collections::BTreeMap;

pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;

#[derive(Deserialize)]
struct Config {
    #[serde(rename = "mcpServers")]
    servers: BTreeMap<String, serde_json::Value>,
}

/// Only local stdio servers are supported. Unknown per-server options fail
/// closed rather than silently discarding client security/transport settings.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StdioServer {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default, rename = "type")]
    transport: Option<String>,
}

pub fn parse_server(bytes: &[u8], name: &str) -> Result<StdioServer> {
    if bytes.len() > MAX_CONFIG_BYTES {
        bail!("MCP configuration exceeds the 1 MiB limit");
    }
    // Do not attach serde errors: unknown fields and invalid values can contain
    // credentials. Neither server names nor config paths are echoed in errors.
    let mut config: Config = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("Invalid MCP configuration; expected a mcpServers object"))?;
    let value = config
        .servers
        .remove(name)
        .ok_or_else(|| anyhow::anyhow!("MCP server is not configured"))?;
    let server: StdioServer = serde_json::from_value(value).map_err(|_| {
        anyhow::anyhow!("Invalid MCP stdio server; supported fields: command, args, env, type")
    })?;
    if server.transport.as_deref().is_some_and(|t| t != "stdio") {
        bail!("Only local stdio MCP servers are supported");
    }
    if server.command.trim().is_empty()
        || server.command.contains('\0')
        || server.args.iter().any(|arg| arg.contains('\0'))
    {
        bail!("MCP command must be nonempty and command/args must contain no NUL bytes");
    }
    if server.env.iter().any(|(key, value)| {
        let mut chars = key.chars();
        !matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
            || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
            || value.contains('\0')
    }) {
        bail!("MCP env must use portable variable names and contain no NUL bytes");
    }
    Ok(server)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_stdio_and_defaults_without_expanding_values() {
        let server = parse_server(br#"{"mcpServers":{"test":{"command":"node","args":["server.js"],"env":{"MODE":"${MODE}"},"type":"stdio"},"remote":{"url":"https://example.invalid"}},"metadata":{}}"#, "test").unwrap();
        assert_eq!(server.command, "node");
        assert_eq!(server.args, ["server.js"]);
        assert_eq!(server.env["MODE"], "${MODE}");
        let server =
            parse_server(br#"{"mcpServers":{"test":{"command":"node"}}}"#, "test").unwrap();
        assert!(server.args.is_empty() && server.env.is_empty());
    }

    #[test]
    fn invalid_config_is_value_blind() {
        let marker = "private-config-sentinel";
        for bytes in [
            format!(r#"{{"mcpServers":{{"test":{{"command":true,"{marker}":1}}}}}}"#),
            format!(
                r#"{{"mcpServers":{{"test":{{"command":"node","env":{{"K":{{"{marker}":1}}}}}}}}}}"#
            ),
            format!(r#"{{"mcpServers":{{"test":{{"command":"node","type":"{marker}"}}}}}}"#),
            marker.to_string(),
        ] {
            let error = parse_server(bytes.as_bytes(), "test")
                .err()
                .expect("refused");
            assert!(!format!("{error:#}").contains(marker));
        }
    }

    #[test]
    fn refuses_unsupported_or_invalid_fields() {
        for server in [
            r#"{"command":"node","url":"https://example.invalid"}"#,
            r#"{"command":"node","type":"http"}"#,
            r#"{"command":" "}"#,
            r#"{"command":"node","args":["\u0000"]}"#,
            r#"{"command":"node","env":{"BAD=NAME":"x"}}"#,
            r#"{"command":"node","env":{"":"x"}}"#,
            r#"{"command":"node","env":{"K":"\u0000"}}"#,
        ] {
            let bytes = format!(r#"{{"mcpServers":{{"test":{server}}}}}"#);
            assert!(parse_server(bytes.as_bytes(), "test").is_err());
        }
        assert!(parse_server(br#"{"mcpServers":{}}"#, "missing").is_err());
        assert!(parse_server(&vec![b' '; MAX_CONFIG_BYTES + 1], "test").is_err());
    }
}
