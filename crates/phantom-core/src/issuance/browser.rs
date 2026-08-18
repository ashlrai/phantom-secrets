//! Browser side-effect injection.
//!
//! Consent engines never open a tab directly; they call [`BrowserOpener::open`]
//! on an injected dep. The real, `open`-crate-backed implementation lives in
//! `phantom-cli` (core has no `open` dependency and stays hermetically
//! testable). Core ships only the [`NoBrowser`] sentinel used for headless
//! runs, `--no-browser`, and unit tests.

/// Opens a URL in the user's default browser.
///
/// Implementations MUST NOT block on the browser process and MUST treat the URL
/// as opaque — it is a consent artifact, never a secret, but it is also never
/// logged beyond the single stderr line the engine itself prints.
pub trait BrowserOpener: Send + Sync {
    /// Attempt to open `url`. Returns `false` when no browser could be launched
    /// (headless / sentinel), so the engine can decide whether to fall back or
    /// simply rely on the user pasting the URL it already printed.
    fn open(&self, url: &str) -> bool;

    /// Whether this opener can actually launch a browser. `false` for
    /// [`NoBrowser`]; engines use it to pick the headless path.
    fn is_available(&self) -> bool {
        true
    }
}

/// Sentinel opener for headless / `--no-browser` / test runs: opens nothing.
///
/// The engine still prints the consent URL to stderr, so a human on a remote
/// box can paste it; and device flow needs no browser at all.
pub struct NoBrowser;

impl BrowserOpener for NoBrowser {
    fn open(&self, _url: &str) -> bool {
        false
    }
    fn is_available(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Test opener that records the URLs it was asked to open.
    pub struct FakeBrowser {
        pub opened: Mutex<Vec<String>>,
    }

    impl FakeBrowser {
        pub fn new() -> Self {
            Self {
                opened: Mutex::new(Vec::new()),
            }
        }
    }

    impl BrowserOpener for FakeBrowser {
        fn open(&self, url: &str) -> bool {
            self.opened.lock().unwrap().push(url.to_string());
            true
        }
    }

    #[test]
    fn nobrowser_reports_unavailable() {
        let b = NoBrowser;
        assert!(!b.open("https://example.com"));
        assert!(!b.is_available());
    }

    #[test]
    fn fake_browser_captures_urls() {
        let b = FakeBrowser::new();
        assert!(b.open("https://example.com/authorize?state=abc"));
        assert_eq!(b.opened.lock().unwrap().len(), 1);
    }
}
