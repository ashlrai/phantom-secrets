use clap::Subcommand;

#[derive(Subcommand)]
pub(crate) enum ValidateAction {
    /// Show or configure validation scheduling; writes require exact terminal consent
    ///
    /// Examples:
    ///   phantom validate schedule hourly
    ///   phantom validate schedule 6h
    ///   phantom validate schedule daily@2am
    ///   phantom validate schedule weekly
    ///   phantom validate schedule --disable
    ///   phantom validate schedule --status
    #[command(verbatim_doc_comment)]
    Schedule {
        /// Schedule interval: hourly, 6h, daily, daily@2am, weekly, disabled
        #[arg(value_name = "INTERVAL")]
        interval: Option<String>,
        /// Show current schedule and staleness without changing anything
        #[arg(long, conflicts_with = "interval")]
        status: bool,
        /// Disable the scheduler
        #[arg(long, conflicts_with = "interval")]
        disable: bool,
    },
    /// Show past validation run history.
    History {
        /// Number of most-recent runs to show (default: 20)
        #[arg(long, short = 'n', value_name = "N")]
        last: Option<usize>,
    },
}
