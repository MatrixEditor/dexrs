//! TUI renderer - 2-pane layout: collapsible class tree + scrollable code/details pane.
//!
//! Layout:
//! ```
//! ┌- Tree ------┬- Code / Details ---------------------------------┐
//! │  packages   │  disasm / class info / code editor               │
//! │  classes    │                                                   │
//! │  members    │                                                   │
//! └-------------┴--------------------------------------------------┘
//! [status bar]
//! ```

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Clear, List, ListItem, ListState, Paragraph, Scrollbar,
        ScrollbarOrientation, ScrollbarState, Wrap,
    },
    Frame,
};

use super::app::{App, AppMode, Focus, MemberKind, TreeItem};
use crate::highlight;

// -- Palette -------------------------------------------------------------------
// All muted RGB values - avoid terminal neons, keep contrast readable but calm.

/// Active-border / accent (steel blue)
const ACCENT: Color = Color::Rgb(95, 135, 175);
/// Inactive border / secondary text (mid gray)
const DIM: Color = Color::Rgb(110, 110, 110);
/// Selected-row background (very subtle dark)
const HIGHLIGHT_BG: Color = Color::Rgb(42, 48, 58);
/// Error / warning (soft amber-red)
const WARN: Color = Color::Rgb(210, 110, 80);
/// Program-counter column (dim gray)
const PC_COLOR: Color = Color::Rgb(100, 100, 110);
/// Code-edit cursor row background (deep slate)
const EDIT_CURSOR_BG: Color = Color::Rgb(30, 50, 75);
/// Code-editor line-edit background (dark warm gray)
const LINE_EDIT_BG: Color = Color::Rgb(55, 48, 40);

/// Section / title text (muted gold)
const TITLE: Color = Color::Rgb(190, 160, 90);
/// Package-header text (same as title)
const PKG_COLOR: Color = Color::Rgb(190, 160, 90);
/// Class-name text (light gray)
const CLASS_COLOR: Color = Color::Rgb(200, 200, 200);
/// Header/key labels in the details pane (mid gray)
const KEY_COLOR: Color = Color::Rgb(120, 120, 130);

/// Hint / informational italic text
const HINT: Color = Color::Rgb(100, 110, 120);

// Member-icon colors
const DIRECT_METHOD_COLOR: Color  = Color::Rgb(120, 165, 210);
const VIRTUAL_METHOD_COLOR: Color = Color::Rgb(100, 185, 175);
const STATIC_FIELD_COLOR: Color   = Color::Rgb(195, 160, 80);
const INSTANCE_FIELD_COLOR: Color = Color::Rgb(170, 135, 70);

// Status-bar backgrounds
const STATUS_BG: Color      = Color::Rgb(28, 28, 32);
const STATUS_EDIT_BG: Color = Color::Rgb(30, 50, 75);
const STATUS_LINE_BG: Color = Color::Rgb(50, 38, 30);

// -- Top-level draw ------------------------------------------------------------

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();

    let [main_area, status_area] = Layout::vertical([
        Constraint::Min(0),
        Constraint::Length(1),
    ]).areas(area);

    let [tree_area, code_area] = Layout::horizontal([
        Constraint::Percentage(28),
        Constraint::Fill(1),
    ]).areas(main_area);

    draw_tree(f, app, tree_area);
    draw_code(f, app, code_area);
    draw_status_bar(f, app, status_area);

    // Overlays (highest z-order last)
    if app.show_help {
        draw_help_overlay(f, area);
    } else if app.show_info {
        draw_info_overlay(f, app, area);
    } else if matches!(app.mode, AppMode::RenameModal | AppMode::FlagsModal) {
        draw_modal_overlay(f, app, area);
    }
}

// -- Loading screen ------------------------------------------------------------

const SPINNER: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// Render a loading/progress screen shown while `build_app_state` runs.
///
/// `tick` is an ever-increasing counter used to animate the spinner.
pub fn draw_loading(
    f: &mut Frame,
    file_name: &str,
    current: usize,
    total: usize,
    tick: u64,
) {
    let area = f.area();

    // Center a narrow box
    let box_w = 52u16.min(area.width.saturating_sub(4));
    let box_h = 10u16.min(area.height.saturating_sub(4));
    let popup = centered_rect(box_w, box_h, area);

    let spinner = SPINNER[(tick as usize) % SPINNER.len()];

    // Gauge: filled / total width
    let inner_w = (popup.width.saturating_sub(4)) as usize;
    let pct = if total == 0 { 0 } else { (current * inner_w) / total };
    let pct = pct.min(inner_w);
    let bar: String = "█".repeat(pct) + &"░".repeat(inner_w.saturating_sub(pct));

    let progress_line = if total > 0 {
        format!(" {current}/{total} classes")
    } else {
        " Reading file…".to_string()
    };

    let lines = vec![
        Line::default(),
        Line::from(vec![
            Span::styled(format!(" {spinner} "), Style::default().fg(ACCENT)),
            Span::styled(
                format!("Loading  {file_name}"),
                Style::default().fg(Color::Rgb(200, 200, 210)),
            ),
        ]),
        Line::default(),
        Line::from(Span::styled(
            format!(" [{bar}]"),
            Style::default().fg(Color::Rgb(90, 130, 170)),
        )),
        Line::from(Span::styled(
            progress_line,
            Style::default().fg(DIM),
        )),
        Line::default(),
        Line::from(Span::styled(
            " Press Esc or q to cancel",
            Style::default().fg(Color::Rgb(100, 100, 100)).add_modifier(Modifier::ITALIC),
        )),
    ];

    let p = Paragraph::new(lines).block(
        Block::default()
            .title(Span::styled(" dexrs ", Style::default().fg(TITLE).add_modifier(Modifier::BOLD)))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT)),
    );
    f.render_widget(p, popup);
}

// -- Tree pane -----------------------------------------------------------------

fn draw_tree(f: &mut Frame, app: &mut App, area: Rect) {
    let active = app.focus == Focus::Tree && app.mode == AppMode::Browse;
    let border_style = if active { Style::default().fg(ACCENT) } else { Style::default().fg(DIM) };

    let title = if app.mode == AppMode::Search {
        format!(" / {} ", app.search)
    } else {
        format!(" Classes [{}] ", app.tree.len())
    };

    let visible_height = area.height.saturating_sub(2) as usize;

    // Clamp tree_scroll so cursor is always visible.
    if app.tree_cursor < app.tree_scroll {
        app.tree_scroll = app.tree_cursor;
    }
    if app.tree_cursor >= app.tree_scroll + visible_height {
        app.tree_scroll = app.tree_cursor - visible_height + 1;
    }

    let items: Vec<ListItem> = app
        .tree
        .iter()
        .enumerate()
        .skip(app.tree_scroll)
        .take(visible_height)
        .map(|(i, item)| tree_item_to_list_item(app, i, item))
        .collect();

    let mut state = ListState::default();
    let cursor_in_view = app.tree_cursor.saturating_sub(app.tree_scroll);
    if !app.tree.is_empty() {
        state.select(Some(cursor_in_view));
    }

    let list = List::new(items)
        .block(
            Block::default()
                .title(Span::styled(title, Style::default().fg(TITLE)))
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .highlight_style(
            Style::default()
                .bg(HIGHLIGHT_BG)
                .add_modifier(Modifier::BOLD),
        );

    f.render_stateful_widget(list, area, &mut state);
}

fn tree_item_to_list_item<'a>(app: &App, _idx: usize, item: &TreeItem) -> ListItem<'a> {
    match item {
        TreeItem::Package { name, expanded } => {
            let icon = if *expanded { "▾" } else { "▸" };
            let label = if name.is_empty() { "(no package)".to_string() } else { name.clone() };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{icon} {label}"),
                    Style::default().fg(PKG_COLOR).add_modifier(Modifier::BOLD),
                ),
            ]))
        }
        TreeItem::Class { class_idx, expanded } => {
            let cls = &app.classes[*class_idx];
            let icon = if *expanded { "▾" } else { "▸" };
            let has_members = !cls.methods.is_empty() || !cls.fields.is_empty();
            let icon = if has_members { icon } else { "·" };
            ListItem::new(Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    format!("{icon} {}", cls.simple_name),
                    Style::default().fg(CLASS_COLOR),
                ),
            ]))
        }
        TreeItem::Member { class_idx, member_idx } => {
            let cls = &app.classes[*class_idx];
            let member = if *member_idx < cls.methods.len() {
                &cls.methods[*member_idx]
            } else {
                &cls.fields[*member_idx - cls.methods.len()]
            };
            let (icon, color) = match member.kind {
                MemberKind::DirectMethod  => ("⬡", DIRECT_METHOD_COLOR),
                MemberKind::VirtualMethod => ("◈", VIRTUAL_METHOD_COLOR),
                MemberKind::StaticField   => ("■", STATIC_FIELD_COLOR),
                MemberKind::InstanceField => ("□", INSTANCE_FIELD_COLOR),
            };
            // Show just the raw method/field name (simpler to read).
            let display_name = if member.raw_name.is_empty() {
                &member.name
            } else {
                &member.raw_name
            };
            ListItem::new(Line::from(vec![
                Span::raw("    "),
                Span::styled(format!("{icon} "), Style::default().fg(color)),
                Span::raw(display_name.to_string()),
            ]))
        }
    }
}

// -- Code pane -----------------------------------------------------------------

fn draw_code(f: &mut Frame, app: &mut App, area: Rect) {
    match &app.mode {
        AppMode::CodeEdit | AppMode::LineEdit => draw_code_editor(f, app, area),
        _ => draw_code_viewer(f, app, area),
    }
}

fn draw_code_viewer(f: &mut Frame, app: &mut App, area: Rect) {
    let active = app.focus == Focus::Code;
    let border_style = if active { Style::default().fg(ACCENT) } else { Style::default().fg(DIM) };

    let (title, content) = build_code_viewer_content(app);

    let total_lines = content.len();
    let visible = area.height.saturating_sub(2);

    let paragraph = Paragraph::new(content)
        .block(
            Block::default()
                .title(Span::styled(title, Style::default().fg(TITLE)))
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .scroll((app.code_scroll, 0))
        .wrap(Wrap { trim: false });

    f.render_widget(paragraph, area);

    if total_lines > visible as usize {
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));
        let mut sb_state =
            ScrollbarState::new(total_lines.saturating_sub(visible as usize))
                .position(app.code_scroll as usize);
        let sb_area = Rect {
            x: area.x + area.width - 1,
            y: area.y + 1,
            width: 1,
            height: visible,
        };
        f.render_stateful_widget(scrollbar, sb_area, &mut sb_state);
    }

    app.code_total_lines = total_lines;
    app.code_visible_height = visible;
}

fn build_code_viewer_content(app: &mut App) -> (String, Vec<Line<'static>>) {
    // Clone the item to avoid holding a reference into app.tree while we mutate app.disasm_cache.
    let Some(item) = app.current_item().cloned() else {
        return (" Details ".to_string(), vec![]);
    };

    match &item {
        TreeItem::Package { name, .. } => {
            let pkg_display = if name.is_empty() { "(no package)" } else { name.as_str() };
            let n_classes = app.classes.iter().filter(|c| &c.package == name).count();
            let lines = vec![
                Line::from(Span::styled(
                    format!("Package: {pkg_display}"),
                    Style::default().fg(TITLE),
                )),
                Line::from(Span::styled(
                    format!("{n_classes} class(es)"),
                    Style::default().fg(DIM),
                )),
            ];
            (format!(" Package - {pkg_display} "), lines)
        }
        TreeItem::Class { class_idx, .. } => {
            let cls = &app.classes[*class_idx];
            let title = format!(" {} ", cls.simple_name);
            let lines = vec![
                key_val("Descriptor", &cls.descriptor),
                key_val("Package", &cls.package),
                key_val("Superclass", &cls.superclass),
                key_val("Flags", &crate::output::format_flags(cls.access_flags)),
                Line::default(),
                Line::from(Span::styled(
                    format!("{} methods,  {} fields", cls.methods.len(), cls.fields.len()),
                    Style::default().fg(DIM),
                )),
                Line::default(),
                Line::from(Span::styled(
                    "Press [->] or [Enter] to expand, then select a method to view its code.",
                    Style::default().fg(HINT).add_modifier(Modifier::ITALIC),
                )),
            ];
            (title, lines)
        }
        TreeItem::Member { class_idx, member_idx } => {
            let ci = *class_idx;
            let mi = *member_idx;

            // Compute disasm on first view; subsequent views use the cache (instant).
            let styled_disasm: Vec<(u32, _)> = {
                let entry = app.get_or_compute_disasm(ci, mi);
                entry.styled.clone()
            };

            let cls = &app.classes[ci];
            let member = if mi < cls.methods.len() {
                &cls.methods[mi]
            } else {
                &cls.fields[mi - cls.methods.len()]
            };
            let title = format!(" {} - {} ", member.kind.label(), member.raw_name);
            let mut lines: Vec<Line> = Vec::new();

            // Signature / type
            lines.push(key_val("Name", &member.name));
            lines.push(key_val("Flags", &crate::output::format_flags(member.access_flags)));

            if let Some(ref info) = member.code_info {
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(info.clone(), Style::default().fg(DIM))));
            }

            if styled_disasm.is_empty() {
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "(abstract / native - no code)",
                    Style::default().fg(DIM).add_modifier(Modifier::ITALIC),
                )));
                if app.is_editable() {
                    lines.push(Line::from(Span::styled(
                        "Press [e] to edit.",
                        Style::default().fg(HINT).add_modifier(Modifier::ITALIC),
                    )));
                }
            } else {
                lines.push(Line::default());
                for (pc, styled) in &styled_disasm {
                    let mut spans = vec![
                        Span::styled(format!("{pc:04x}"), Style::default().fg(PC_COLOR)),
                        Span::raw("  "),
                    ];
                    spans.extend(highlight::to_tui_line(styled).spans);
                    lines.push(Line::from(spans));
                }
                if app.is_editable() {
                    lines.push(Line::default());
                    lines.push(Line::from(Span::styled(
                        "Press [e] to edit instructions inline.",
                        Style::default().fg(HINT).add_modifier(Modifier::ITALIC),
                    )));
                }
            }
            (title, lines)
        }
    }
}

fn key_val(key: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{key:<14}"),
            Style::default().fg(KEY_COLOR),
        ),
        Span::raw(value.to_string()),
    ])
}

// -- Inline code editor --------------------------------------------------------

fn draw_code_editor(f: &mut Frame, app: &mut App, area: Rect) {
    let in_line_edit = app.mode == AppMode::LineEdit;
    let border_style = Style::default().fg(ACCENT);

    let cursor = app.code_edit.cursor;
    let scroll = app.code_edit.scroll;
    let visible_h = area.height.saturating_sub(4) as usize; // -4: borders + header + hint row

    // Clamp scroll
    if cursor < scroll as usize { app.code_edit.scroll = cursor as u16; }
    if cursor >= scroll as usize + visible_h { app.code_edit.scroll = (cursor - visible_h + 1) as u16; }
    let scroll = app.code_edit.scroll as usize;

    let dirty_mark = if app.code_edit.dirty { " ●" } else { "" };
    let title = format!(" ✎ {} [code edit{}] ", app.code_edit.method_name, dirty_mark);

    let (regs, ins, outs) = app.code_edit.registers;
    let header = format!(".registers {regs} {ins} {outs}");

    let mut lines: Vec<Line> = Vec::new();

    // Header line (non-editable but informational)
    lines.push(Line::from(Span::styled(
        header,
        Style::default().fg(Color::Rgb(160, 120, 185)),
    )));
    lines.push(Line::default());

    // Instruction lines
    for (i, line_text) in app.code_edit.lines.iter().enumerate() {
        if i < scroll || i >= scroll + visible_h { continue; }

        let is_cursor = i == cursor;
        let has_error = app.code_edit.errors.contains_key(&i);

        let display_text = if is_cursor && in_line_edit {
            // Show the edit buffer with cursor indicator
            format!("{}_", app.code_edit.line_buf)
        } else {
            line_text.clone()
        };

        let num_span = Span::styled(
            format!("{:>3} ", i + 1),
            Style::default().fg(DIM),
        );

        let text_style = if is_cursor && !in_line_edit {
            Style::default().bg(EDIT_CURSOR_BG).fg(Color::Rgb(220, 220, 230)).add_modifier(Modifier::BOLD)
        } else if is_cursor && in_line_edit {
            Style::default().bg(LINE_EDIT_BG).fg(Color::Rgb(220, 190, 130))
        } else if has_error {
            Style::default().fg(WARN)
        } else {
            Style::default().fg(Color::Rgb(195, 195, 200))
        };

        lines.push(Line::from(vec![
            num_span,
            Span::styled(display_text, text_style),
        ]));

        // Show error on next line
        if let Some(err) = app.code_edit.errors.get(&i) {
            lines.push(Line::from(Span::styled(
                format!("     ↳ {err}"),
                Style::default().fg(WARN),
            )));
        }
    }

    // Bottom hint row
    lines.push(Line::default());
    let hint = if in_line_edit {
        "[Enter] Confirm  [Esc] Cancel"
    } else if app.code_edit.errors.is_empty() && app.code_edit.dirty {
        "[w] Save  [Esc] Discard  [↑↓] Navigate  [Enter/i] Edit line  [a] Append  [dd] Delete"
    } else {
        "[w] Save  [Esc] Discard  [↑↓] Navigate  [Enter/i] Edit line  [a] Append  [O] Insert  [dd] Delete"
    };
    lines.push(Line::from(Span::styled(hint, Style::default().fg(DIM))));

    // Top-level error
    if let Some(err) = app.code_edit.errors.get(&0).filter(|_| app.code_edit.lines.is_empty() || !app.code_edit.errors.contains_key(&0)) {
        lines.push(Line::from(Span::styled(
            format!("Error: {err}"),
            Style::default().fg(WARN).add_modifier(Modifier::BOLD),
        )));
    }

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .title(Span::styled(title, Style::default().fg(TITLE)))
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(paragraph, area);
}

// -- Status bar ----------------------------------------------------------------

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let (bg, fg, hints) = match &app.mode {
        AppMode::Search => (
            STATUS_BG,
            Color::Rgb(180, 170, 120),
            format!(" Search: {}  [Enter] Apply  [Esc] Cancel", app.search),
        ),
        AppMode::CodeEdit => (
            STATUS_EDIT_BG,
            Color::Rgb(160, 185, 210),
            " [↑↓] Navigate  [Enter/i] Edit  [a] Append  [dd] Delete  [w] Save  [Esc] Discard ".to_string(),
        ),
        AppMode::LineEdit => (
            STATUS_LINE_BG,
            Color::Rgb(210, 185, 140),
            " [Enter] Confirm line  [Esc] Cancel ".to_string(),
        ),
        AppMode::RenameModal | AppMode::FlagsModal => (
            STATUS_BG,
            Color::Rgb(160, 185, 210),
            " [Enter] Apply  [Esc] Cancel ".to_string(),
        ),
        AppMode::Browse if app.is_editable() => (
            STATUS_BG,
            Color::Rgb(140, 150, 160),
            " [↑↓/hjkl] Navigate  [Tab] Toggle pane  [/] Search  [e] Edit code  [r] Rename  [f] Flags  [i] Info  [?] Help  [q] Quit ".to_string(),
        ),
        _ => (
            STATUS_BG,
            Color::Rgb(140, 150, 160),
            " [↑↓/hjkl] Navigate  [Tab] Toggle pane  [/] Search  [i] Info  [?] Help  [q] Quit ".to_string(),
        ),
    };
    let bar = Paragraph::new(hints).style(Style::default().bg(bg).fg(fg));
    f.render_widget(bar, area);
}

// -- Help overlay --------------------------------------------------------------

fn draw_help_overlay(f: &mut Frame, area: Rect) {
    let width = 62u16.min(area.width.saturating_sub(4));
    let height = 32u16.min(area.height.saturating_sub(4));
    let popup = centered_rect(width, height, area);

    f.render_widget(Clear, popup);

    let text = vec![
        Line::from(Span::styled(" Keyboard Shortcuts", Style::default().fg(Color::Rgb(200, 200, 210)).add_modifier(Modifier::BOLD))),
        Line::default(),
        Line::from(Span::styled(" Navigation", Style::default().fg(TITLE))),
        Line::from("  [↑/k]  [↓/j]        Move up / down in tree"),
        Line::from("  [->/l] [Enter]        Expand class / enter code pane"),
        Line::from("  [←/h]  [Esc]         Collapse / go back to tree"),
        Line::from("  [Tab]               Toggle focus tree ↔ code"),
        Line::from("  [PgUp] [PgDn]        Scroll code pane by page"),
        Line::from("  [/]                  Search / filter classes"),
        Line::default(),
        Line::from(Span::styled(" Editing (requires -o flag)", Style::default().fg(TITLE))),
        Line::from("  [e]                  Enter inline code editor"),
        Line::from("  [r]                  Rename selected class"),
        Line::from("  [f]                  Set access flags"),
        Line::default(),
        Line::from(Span::styled(" Code Editor", Style::default().fg(TITLE))),
        Line::from("  [↑/k]  [↓/j]        Move cursor between lines"),
        Line::from("  [Enter] or [i]       Edit the highlighted line"),
        Line::from("  [a]                  Append new line after cursor"),
        Line::from("  [O]                  Insert new line before cursor"),
        Line::from("  [dd]                 Delete current line"),
        Line::from("  [w]                  Save (compile + write)"),
        Line::from("  [Esc]               Discard all edits"),
        Line::default(),
        Line::from(Span::styled(" Line Edit", Style::default().fg(TITLE))),
        Line::from("  Type freely          Instruction text input"),
        Line::from("  [Enter]              Confirm edit"),
        Line::from("  [Esc]               Cancel line edit"),
        Line::default(),
        Line::from("  [i]   File info    [?]   This help    [q]   Quit"),
    ];

    let p = Paragraph::new(text).block(
        Block::default()
            .title(" Help ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT)),
    );
    f.render_widget(p, popup);
}

// -- Info overlay --------------------------------------------------------------

fn draw_info_overlay(f: &mut Frame, app: &App, area: Rect) {
    let width = 60u16.min(area.width.saturating_sub(4));
    let height = 10u16.min(area.height.saturating_sub(4));
    let popup = centered_rect(width, height, area);

    f.render_widget(Clear, popup);

    let lines: Vec<Line> = app.file_info.lines().map(|l| Line::from(l.to_string())).collect();
    let p = Paragraph::new(lines).block(
        Block::default()
            .title(" File Info ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT)),
    );
    f.render_widget(p, popup);
}

// -- Modal overlay (rename / flags) --------------------------------------------

fn draw_modal_overlay(f: &mut Frame, app: &App, area: Rect) {
    let (title, prompt) = match &app.mode {
        AppMode::RenameModal => (" Rename Class ", "New descriptor (e.g. Lcom/example/Foo;):"),
        AppMode::FlagsModal => (" Set Access Flags ", "Flags (decimal or 0x hex, e.g. 0x1 = public):"),
        _ => return,
    };

    let width = 60u16.min(area.width.saturating_sub(4));
    let height = 7u16.min(area.height.saturating_sub(4));
    let popup = centered_rect(width, height, area);

    f.render_widget(Clear, popup);

    let mut lines = vec![
        Line::from(Span::styled(prompt, Style::default().fg(Color::Rgb(190, 190, 200)))),
        Line::default(),
        Line::from(vec![
            Span::raw("> "),
            Span::styled(
                app.modal.buffer.clone(),
                Style::default().fg(TITLE).add_modifier(Modifier::BOLD),
            ),
            Span::styled("█", Style::default().fg(TITLE)),
        ]),
    ];

    if let Some(ref err) = app.modal.error {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            format!("⚠ {err}"),
            Style::default().fg(WARN),
        )));
    }

    let p = Paragraph::new(lines).block(
        Block::default()
            .title(Span::styled(title, Style::default().fg(TITLE).add_modifier(Modifier::BOLD)))
            .title_bottom(Span::styled(" [Enter] Apply  [Esc] Cancel ", Style::default().fg(DIM)))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(ACCENT)),
    );
    f.render_widget(p, popup);
}

// -- Helpers -------------------------------------------------------------------

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect { x, y, width, height }
}
