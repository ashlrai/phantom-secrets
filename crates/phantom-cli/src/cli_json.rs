//! Exhaustive global output policy, independent of parsing and execution.
use crate::cli_actions::{
    AgentAction, CloudAction, CryptoAction, ExpiryAction, LeaksAction, McpAction, TeamAction,
    VaultAction, WorkspaceCliAction,
};
use crate::{commands, Commands};

/// Route the global `--json` flag to the command that runs.
///
/// `--json` is a global flag, so clap accepts it on every command. Commands
/// with no JSON output used to ignore it and print human text with exit 0,
/// which a script then fails to parse. This returns the command path when the
/// command has no JSON output, and otherwise makes sure the command's own
/// `--json` flag is set.
///
/// The match is exhaustive on purpose: a new command must decide here.
pub(crate) fn apply_global_json(command: &mut Commands) -> Result<(), &'static str> {
    use commands::audit::AuditAction as A;
    match command {
        // Commands that read the global flag themselves.
        Commands::Status { .. }
        | Commands::Sync { .. }
        | Commands::Doctor { .. }
        | Commands::Check { .. }
        | Commands::Agent {
            action: AgentAction::Report { .. },
        }
        | Commands::Agent {
            action: AgentAction::Doctor { .. },
        }
        | Commands::Why { .. }
        | Commands::Crypto {
            action: CryptoAction::Inventory { .. },
        }
        | Commands::Audit {
            action: A::Verify { .. } | A::Feed { .. },
        }
        | Commands::Setup { status: true, .. }
        | Commands::Grant { .. }
        | Commands::Vault {
            action: VaultAction::MigrateLinux,
        } => Ok(()),
        Commands::Rotate {
            batch,
            shadow,
            provider,
            name,
            ..
        } => {
            if *batch || (!*shadow && (provider.is_some() || name.is_some())) {
                Ok(())
            } else {
                Err("phantom rotate (without --batch or --name)")
            }
        }
        Commands::Validate {
            action, promote, ..
        } => {
            if action.is_none() && promote.is_some() {
                Err("phantom validate --promote")
            } else {
                Ok(())
            }
        }
        // Commands with their own `--json` flag.
        Commands::List { json, .. }
        | Commands::Agent {
            action: AgentAction::Status { json },
        }
        | Commands::Leaks {
            action: LeaksAction::Plan { json, .. },
        }
        | Commands::SecretsExpiringSoon { json, .. }
        | Commands::Expiry {
            action: ExpiryAction::Enforce { json, .. },
        }
        | Commands::Workspace {
            action: WorkspaceCliAction::Plan { json } | WorkspaceCliAction::Status { json, .. },
        }
        | Commands::Audit {
            action:
                A::Show { json, .. }
                | A::Stats { json, .. }
                | A::Anomalies { json, .. }
                | A::Incidents { json, .. }
                | A::Alerts { json, .. },
        } => {
            *json = true;
            Ok(())
        }
        // Audit exports whose output is JSON unless another format is chosen.
        Commands::Audit {
            action: A::Export { format, .. },
        } => json_format(format, "phantom audit export --format csv"),
        Commands::Audit {
            action: A::Analytics { format, .. },
        } => json_format(format, "phantom audit analytics --format csv"),
        Commands::Audit {
            action: A::ExportRange { format, .. },
        } => json_format(format, "phantom audit export-range --format csv"),
        Commands::Audit {
            action: A::Report { .. },
        } => Ok(()),
        // Commands with no JSON output.
        Commands::Audit {
            action: A::Tail { .. },
        } => Err("phantom audit tail"),
        Commands::Audit { action: A::Path } => Err("phantom audit path"),
        Commands::Agent {
            action: AgentAction::Setup { .. },
        } => Err("phantom agent setup"),
        Commands::Expiry {
            action: ExpiryAction::Set { .. },
        } => Err("phantom expiry set"),
        Commands::Expiry {
            action: ExpiryAction::Rotate { .. },
        } => Err("phantom expiry rotate"),
        Commands::Workspace {
            action: WorkspaceCliAction::Apply { .. },
        } => Err("phantom workspace apply"),
        Commands::Init { .. } => Err("phantom init"),
        Commands::Setup { .. } => Err("phantom setup"),
        Commands::Completion { .. } => Err("phantom completion"),
        Commands::Mcp {
            action: McpAction::Serve,
        } => Err("phantom mcp serve"),
        Commands::McpApprove { .. } => Err("phantom mcp-approve"),
        Commands::Exec { .. } => Err("phantom exec"),
        Commands::Start { .. } => Err("phantom start"),
        Commands::Stop => Err("phantom stop"),
        Commands::Add { .. } => Err("phantom add"),
        Commands::Remove { .. } => Err("phantom remove"),
        Commands::Reveal { .. } => Err("phantom reveal"),
        Commands::GitCredential { .. } => Err("phantom git-credential"),
        Commands::Copy { .. } => Err("phantom copy"),
        Commands::Env { .. } => Err("phantom env"),
        Commands::Login => Err("phantom login"),
        Commands::Logout => Err("phantom logout"),
        // Read the global flag themselves (still behind the trusted-terminal
        // consent gate, like their text output).
        Commands::Cloud {
            action: CloudAction::Status,
        } => Ok(()),
        Commands::Cloud {
            action: CloudAction::Push,
        } => Err("phantom cloud push"),
        Commands::Cloud {
            action: CloudAction::Pull { .. },
        } => Err("phantom cloud pull"),
        Commands::Team { action } => match action {
            TeamAction::List => Ok(()),
            TeamAction::Create { .. } => Err("phantom team create"),
            TeamAction::Members { .. } => Err("phantom team members"),
            TeamAction::Invite { .. } => Err("phantom team invite"),
            TeamAction::KeyPublish { .. } => Err("phantom team key-publish"),
            TeamAction::VaultPush { .. } => Err("phantom team vault-push"),
            TeamAction::VaultPull { .. } => Err("phantom team vault-pull"),
            TeamAction::Revoke { .. } => Err("phantom team revoke"),
            TeamAction::RotateVault { .. } => Err("phantom team rotate-vault"),
        },
        Commands::Pull { .. } => Err("phantom pull"),
        // `export --json` is a hidden legacy plaintext flag kept only to fail
        // closed with its own message; never turn it on from here.
        Commands::Export { json: true, .. } => Ok(()),
        Commands::Export { .. } => Err("phantom export"),
        Commands::Import { .. } => Err("phantom import"),
        Commands::Wrap { .. } => Err("phantom wrap"),
        Commands::Unwrap => Err("phantom unwrap"),
        Commands::Redact { .. } => Err("phantom redact"),
        Commands::Upgrade { .. } => Err("phantom upgrade"),
        Commands::Watch { .. } => Err("phantom watch"),
        Commands::Open { .. } => Err("phantom open"),
        Commands::ClearClipboardAfter { .. } => Err("phantom __clear-clipboard-after"),
    }
}

fn json_format(format: &str, otherwise: &'static str) -> Result<(), &'static str> {
    if format == "json" {
        Ok(())
    } else {
        Err(otherwise)
    }
}
