//! Terminal color adapters for disassembly [`Highlight`] spans.
//!
//! This module is intentionally thin: all semantic knowledge about which parts
//! of an instruction carry which meaning lives in the library's
//! [`dexrs::file::dump`] module.  Here we only translate [`Highlight`] tags to
//! the two presentation targets we support - ratatui (TUI) and crossterm (CLI).

use crossterm::style::Stylize;
#[cfg(feature = "tui")]
use dexrs::file::dump::StyledLine;
use dexrs::file::dump::{Highlight, Span};
#[cfg(feature = "tui")]
use ratatui::{
    style::{Color, Style},
    text::{Line, Span as TuiSpan},
};

// Muted, low-contrast palette - readable on both dark and light backgrounds.
//   Opcode       dusty gold         #C8A96A
//   Register     soft sage          #7BAF7B
//   Immediate    muted mauve        #A07BA0
//   Offset       slate blue-gray    #7A9BAF
//   StringLit    warm sand          #C8A07A
//   Ref          soft periwinkle    #7A9BC8
//   Comment      dim gray           #666666
#[cfg(feature = "tui")]
const C_OPCODE:  Color = Color::Rgb(200, 169, 106);
#[cfg(feature = "tui")]
const C_REG:     Color = Color::Rgb(123, 175, 123);
#[cfg(feature = "tui")]
const C_IMM:     Color = Color::Rgb(160, 123, 160);
#[cfg(feature = "tui")]
const C_OFFSET:  Color = Color::Rgb(122, 155, 175);
#[cfg(feature = "tui")]
const C_STR:     Color = Color::Rgb(200, 160, 122);
#[cfg(feature = "tui")]
const C_REF:     Color = Color::Rgb(122, 155, 200);
#[cfg(feature = "tui")]
const C_COMMENT: Color = Color::Rgb(102, 102, 102);

#[cfg(feature = "tui")]
fn hl_style(hl: Highlight) -> Style {
    match hl {
        Highlight::Opcode        => Style::default().fg(C_OPCODE),
        Highlight::Register      => Style::default().fg(C_REG),
        Highlight::Immediate     => Style::default().fg(C_IMM),
        Highlight::Offset        => Style::default().fg(C_OFFSET),
        Highlight::StringLiteral => Style::default().fg(C_STR),
        Highlight::Ref           => Style::default().fg(C_REF),
        Highlight::Comment       => Style::default().fg(C_COMMENT),
        Highlight::Plain         => Style::default(),
    }
}

/// Convert a [`StyledLine`] to a ratatui [`Line`] with per-span styling.
#[cfg(feature = "tui")]
pub fn to_tui_line(styled: &StyledLine) -> Line<'static> {
    Line::from(
        styled
            .iter()
            .map(|s| TuiSpan::styled(s.text.clone(), hl_style(s.hl)))
            .collect::<Vec<_>>(),
    )
}

/// Render a [`StyledLine`] to an ANSI-colored string (CLI).
///
/// When `color` is `false` the spans are concatenated without escape codes.
pub fn to_cli_string(styled: &[Span], color: bool) -> String {
    if !color {
        return styled.iter().map(|s| s.text.as_str()).collect();
    }
    let mut out = String::new();
    for s in styled {
        // CLI uses the 8-color ANSI subset (wider terminal compat).
        let colored = match s.hl {
            Highlight::Opcode        => format!("{}", s.text.as_str().yellow()),
            Highlight::Register      => format!("{}", s.text.as_str().green()),
            Highlight::Immediate     => format!("{}", s.text.as_str().magenta()),
            Highlight::Offset        => format!("{}", s.text.as_str().blue()),
            Highlight::StringLiteral => format!("{}", s.text.as_str().dark_yellow()),
            Highlight::Ref           => format!("{}", s.text.as_str().cyan()),
            Highlight::Comment       => format!("{}", s.text.as_str().dark_grey()),
            Highlight::Plain         => s.text.clone(),
        };
        out.push_str(&colored);
    }
    out
}
