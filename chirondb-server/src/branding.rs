//! The banner the terminal front ends print on startup.
//!
//! The wordmark is here rather than inline in the two call sites because both
//! the embedded console and the `chironql` client show it, and a product name
//! rendered two slightly different ways is the kind of thing nobody notices
//! until a screenshot goes out.

use std::io::IsTerminal;

/// `CHIRONDB`, five rows of block capitals. Widest row is 47 columns, which
/// fits any terminal wide enough to be usable for tabular query results.
const WORDMARK: [&str; 5] = [
    " ███  █   █ █████ ████   ███  █   █ ████  ████",
    "█   █ █   █   █   █   █ █   █ ██  █ █   █ █   █",
    "█     █████   █   ████  █   █ █ █ █ █   █ ████",
    "█   █ █   █   █   █  █  █   █ █  ██ █   █ █   █",
    " ███  █   █ █████ █   █  ███  █   █ ████  ████",
];

/// The logo's arrow, five rows of seven columns, printed white beside the
/// wordmark the way it sits beside it in the logo.
const MARK: [&str; 5] = ["   ████", "     ██", "   ███ ", " ███   ", "███    "];

/// Left and right ends of the wordmark gradient — the logo's blue into its
/// violet, in that order.
const GRADIENT: ((u8, u8, u8), (u8, u8, u8)) = ((59, 130, 246), (139, 92, 246));

/// Longest wordmark row, used as the gradient's span so the colour ramp is the
/// same on every row rather than restarting per row length.
const SPAN: usize = 47;

/// The startup banner: the wordmark, the `Gauss` lockup above it, and whatever
/// status the caller wants under it (version, role, where it is connected).
///
/// Colour is decided here, once: escape sequences are emitted only when stdout
/// is a terminal that has not asked to be left alone. Piped output and
/// `NO_COLOR` get the same banner in plain text, so a captured log keeps the
/// branding without the noise.
pub fn banner(status: &str) -> String {
    render(status, color_wanted())
}

/// Clears the screen, its scrollback and homes the cursor.
///
/// Empty when stdout is not a terminal that can act on it, so a piped session
/// writes no escape sequence into whatever is collecting its output. This is
/// not gated on `NO_COLOR`: clearing is not colour, and someone who turned
/// colour off still means `clear` to clear.
pub fn clear() -> &'static str {
    if terminal() {
        "\x1b[H\x1b[2J\x1b[3J"
    } else {
        ""
    }
}

fn terminal() -> bool {
    std::io::stdout().is_terminal() && !matches!(std::env::var("TERM").as_deref(), Ok("dumb"))
}

fn color_wanted() -> bool {
    terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn render(status: &str, color: bool) -> String {
    let mut out = String::new();
    out.push('\n');
    out.push_str(&dim("         Gauss", color));
    out.push('\n');
    for (mark, row) in MARK.iter().zip(WORDMARK) {
        out.push_str(&white(mark, color));
        out.push(' ');
        out.push_str(&gradient_row(row, color));
        out.push('\n');
    }
    out.push('\n');
    out.push_str(status);
    out
}

/// One wordmark row, coloured left to right across [`SPAN`].
///
/// A new escape sequence is emitted only when the colour actually changes,
/// which keeps a row to a handful of them instead of one per column.
fn gradient_row(row: &str, color: bool) -> String {
    if !color {
        return row.to_string();
    }
    let ((r0, g0, b0), (r1, g1, b1)) = GRADIENT;
    let mut out = String::new();
    let mut last = None;
    for (column, ch) in row.chars().enumerate() {
        if ch == ' ' {
            out.push(ch);
            continue;
        }
        let t = column as f32 / (SPAN - 1) as f32;
        let rgb = (lerp(r0, r1, t), lerp(g0, g1, t), lerp(b0, b1, t));
        if last != Some(rgb) {
            out.push_str(&format!("\x1b[38;2;{};{};{}m", rgb.0, rgb.1, rgb.2));
            last = Some(rgb);
        }
        out.push(ch);
    }
    if last.is_some() {
        out.push_str("\x1b[0m");
    }
    out
}

fn white(text: &str, color: bool) -> String {
    if color {
        format!("\x1b[1;97m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

fn dim(text: &str, color: bool) -> String {
    if color {
        format!("\x1b[2m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

fn lerp(from: u8, to: u8, t: f32) -> u8 {
    (from as f32 + (to as f32 - from as f32) * t).round() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_mode_emits_no_escape_sequences() {
        let banner = render("ChironDB · console", false);
        assert!(!banner.contains('\x1b'), "{banner}");
        assert!(banner.contains("ChironDB · console"));
        assert!(banner.contains(WORDMARK[0]));
        assert!(banner.contains(MARK[0]));
        assert!(banner.contains("Gauss"));
    }

    /// Every escape sequence opened on a row is closed on that row, so a
    /// resized or interrupted terminal never keeps the colour afterwards.
    #[test]
    fn coloured_rows_reset_themselves() {
        for row in WORDMARK {
            let rendered = gradient_row(row, true);
            assert!(
                rendered.starts_with(' ') || rendered.starts_with('\x1b'),
                "{rendered}"
            );
            assert!(rendered.ends_with("\x1b[0m"), "{rendered}");
        }
    }

    /// The test harness's stdout is not a terminal, so this also pins the
    /// piped behaviour: nothing is written rather than an escape nobody can
    /// act on.
    #[test]
    fn clear_writes_nothing_without_a_terminal() {
        assert_eq!(clear(), "");
    }

    #[test]
    fn the_status_line_is_the_last_thing_printed() {
        let banner = render("v9 · console attached", true);
        assert!(banner.ends_with("v9 · console attached"), "{banner}");
    }
}
