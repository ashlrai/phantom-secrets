/// Stack size for the real main thread.
///
/// Windows gives the process main thread a 1 MiB stack (unix platforms give
/// 8 MiB), and debug-build stack frames are large enough to overflow that
/// (see the identical trampoline in phantom-cli's main.rs). The tokio
/// runtime's `block_on` drives the root server future on the calling
/// thread, so give it an explicit, platform-independent stack size.
const MAIN_STACK_SIZE: usize = 16 * 1024 * 1024;

fn main() -> anyhow::Result<()> {
    let handle = std::thread::Builder::new()
        .name("phantom-mcp-main".into())
        .stack_size(MAIN_STACK_SIZE)
        .spawn(run)?;
    match handle.join() {
        Ok(result) => result,
        // Propagate a panic on the worker thread as if it happened here so
        // the process still dies with the standard panic exit status.
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[tokio::main]
async fn run() -> anyhow::Result<()> {
    phantom_mcp::run_stdio_server().await
}
