use anyhow::Result;

pub fn run() -> Result<()> {
    anyhow::bail!(
        "External proxy stop is disabled because Phantom does not persist a process identifier or control bearer. Stop a foreground `phantom start` from its owning trusted terminal with Ctrl-C; `phantom exec` stops its own proxy when the child exits."
    )
}
