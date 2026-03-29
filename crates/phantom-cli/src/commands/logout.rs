use anyhow::Result;
use colored::Colorize;
use phantom_core::auth;

pub fn run() -> Result<()> {
    auth::clear_token()?;
    println!("{}  Logged out", "ok".green().bold());
    Ok(())
}
