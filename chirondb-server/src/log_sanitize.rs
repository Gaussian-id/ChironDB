//! Log hygiene for client-influenced text (RT-OBS-1).
//!
//! Parse errors, rejected identifiers and other request-derived messages are
//! logged verbatim by default. Raw control bytes there can forge log lines
//! (`\n`) or drive an operator's terminal (`\x1b[...`). Every logging site that
//! interpolates untrusted text routes it through [`untrusted`], which escapes
//! control and bidi-override characters in `escape_debug` style and caps the
//! length. API response bodies are unchanged.

use std::fmt::Display;

/// Maximum number of characters of untrusted text kept in one log field.
pub(crate) const MAX_LOGGED_CHARS: usize = 512;

/// Returns `text` with control/bidi characters escaped and at most
/// [`MAX_LOGGED_CHARS`] characters kept, for use as a log field value.
pub(crate) fn untrusted(text: impl Display) -> String {
    let text = text.to_string();
    let mut out = String::with_capacity(text.len().min(MAX_LOGGED_CHARS * 2));
    let mut chars = text.chars();
    for ch in chars.by_ref().take(MAX_LOGGED_CHARS) {
        if ch.is_control()
            || matches!(ch, '\u{2028}' | '\u{2029}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
        {
            out.extend(ch.escape_debug());
        } else {
            out.push(ch);
        }
    }
    if chars.next().is_some() {
        out.push_str("...[truncated]");
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use super::{MAX_LOGGED_CHARS, untrusted};

    #[test]
    fn escapes_control_and_bidi_characters() {
        assert_eq!(
            untrusted("a\x1b[31mred\nforged\0\r\t\u{202E}z"),
            "a\\u{1b}[31mred\\nforged\\0\\r\\t\\u{202e}z"
        );
        assert_eq!(
            untrusted("plain ascii and ünïcode"),
            "plain ascii and ünïcode"
        );
    }

    #[test]
    fn caps_length_on_char_boundaries() {
        let long = "é".repeat(MAX_LOGGED_CHARS + 10);
        let out = untrusted(&long);
        assert!(out.ends_with("...[truncated]"));
        assert_eq!(out.chars().filter(|&c| c == 'é').count(), MAX_LOGGED_CHARS);
        assert_eq!(
            untrusted("x".repeat(MAX_LOGGED_CHARS)).len(),
            MAX_LOGGED_CHARS
        );
    }

    #[derive(Clone, Default)]
    pub(crate) struct Capture(pub(crate) Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Serializes log capture against tests that hit the same callsites
    /// without a subscriber: a parallel unsubscribed hit can leave a callsite
    /// disabled for the capturing thread, dropping the line under test.
    static CAPTURE_LOCK: Mutex<()> = Mutex::new(());

    /// Runs `f` under a plain-text fmt subscriber and returns what it logged.
    pub(crate) fn capture_logs(f: impl FnOnce()) -> String {
        let _serial = CAPTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let capture = Capture::default();
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        String::from_utf8(capture.0.lock().unwrap().clone()).unwrap()
    }
}
