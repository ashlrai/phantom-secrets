use std::ffi::OsString;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaunchMode {
    Stdio,
    Version,
}

fn launch_mode(args: impl IntoIterator<Item = OsString>) -> Result<LaunchMode, ()> {
    let args = args.into_iter().collect::<Vec<_>>();
    match args.as_slice() {
        [] => Ok(LaunchMode::Stdio),
        [arg] if arg == "--version" => Ok(LaunchMode::Version),
        _ => Err(()),
    }
}

/// Stack size for the real MCP stdio thread.
///
/// Windows gives the process main thread a 1 MiB stack (unix platforms give
/// 8 MiB), and debug-build stack frames are large enough to overflow that
/// (see the identical trampoline in phantom-cli's main.rs). The tokio
/// runtime's `block_on` drives the root server future on the calling
/// thread, so give it an explicit, platform-independent stack size.
const MAIN_STACK_SIZE: usize = 16 * 1024 * 1024;

fn main() -> anyhow::Result<()> {
    match launch_mode(std::env::args_os().skip(1)) {
        Ok(LaunchMode::Version) => {
            println!("phantom-mcp {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Ok(LaunchMode::Stdio) => {}
        Err(()) => {
            // Do not echo unexpected arguments: they may contain sensitive data.
            eprintln!("usage: phantom-mcp [--version]");
            std::process::exit(2);
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_arguments_select_stdio() {
        assert_eq!(launch_mode(Vec::new()), Ok(LaunchMode::Stdio));
    }

    #[test]
    fn exact_version_flag_selects_version() {
        assert_eq!(
            launch_mode([OsString::from("--version")]),
            Ok(LaunchMode::Version)
        );
    }

    #[test]
    fn unexpected_arguments_are_rejected() {
        for args in [
            vec![OsString::from("-V")],
            vec![OsString::from("--help")],
            vec![OsString::from("--version"), OsString::from("extra")],
        ] {
            assert_eq!(launch_mode(args), Err(()));
        }
    }
}
