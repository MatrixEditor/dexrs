use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use std::time::Duration;

use super::app::{App, AppMode, Focus};

pub enum Action {
    Quit,
    Continue,
}

fn handle_browse(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    // Global quit
    if matches!(code, KeyCode::Char('q') | KeyCode::Char('Q'))
        || (code == KeyCode::Char('c') && mods.contains(KeyModifiers::CONTROL))
    {
        // Signal quit via a special code — handled by returning Quit in the outer loop.
        // We re-use the Action enum by setting a flag. Easier: just set a quit flag.
        // Actually we can't return from here, so we'll use an app flag.
        app.show_help = false; // placeholder; handled below in outer match
        // We need to bubble Quit up. Let's abuse show_help=false as a sentinel.
        // Better: add a quit flag to App.
        // For now let's leave this handled in the outer function.
        return;
    }

    match code {
        KeyCode::Char('q') | KeyCode::Char('Q') => {}

        // Focus toggle
        KeyCode::Tab | KeyCode::BackTab => {
            app.focus = match app.focus {
                Focus::Tree => Focus::Code,
                Focus::Code => Focus::Tree,
            };
        }

        // Navigation
        KeyCode::Up | KeyCode::Char('k') => match app.focus {
            Focus::Tree => app.tree_up(),
            Focus::Code => app.scroll_code_up(),
        },
        KeyCode::Down | KeyCode::Char('j') => match app.focus {
            Focus::Tree => app.tree_down(),
            Focus::Code => app.scroll_code_down(),
        },
        KeyCode::PageUp => match app.focus {
            Focus::Tree => { for _ in 0..10 { app.tree_up(); } }
            Focus::Code => app.page_code_up(),
        },
        KeyCode::PageDown => match app.focus {
            Focus::Tree => { for _ in 0..10 { app.tree_down(); } }
            Focus::Code => app.page_code_down(),
        },

        // Tree: expand/collapse/select
        KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
            app.toggle_expand();
        }
        KeyCode::Left | KeyCode::Char('h') => {
            if app.focus == Focus::Code {
                app.focus = Focus::Tree;
            } else {
                app.collapse_or_parent();
            }
        }
        KeyCode::Esc => {
            if app.focus == Focus::Code {
                app.focus = Focus::Tree;
            }
        }

        // Search
        KeyCode::Char('/') => {
            app.focus = Focus::Tree;
            app.mode = AppMode::Search;
        }

        // Overlays
        KeyCode::Char('?') => app.show_help = !app.show_help,
        KeyCode::Char('i') => app.show_info = !app.show_info,

        // Edit operations (require source_bytes)
        KeyCode::Char('e') if app.is_editable() => {
            app.show_help = false;
            app.show_info = false;
            app.begin_code_edit();
        }
        KeyCode::Char('r') if app.is_editable() => {
            app.show_help = false;
            app.show_info = false;
            app.begin_rename_modal();
        }
        KeyCode::Char('f') if app.is_editable() => {
            app.show_help = false;
            app.show_info = false;
            app.begin_flags_modal();
        }

        _ => {}
    }
}

fn handle_code_edit(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => app.cancel_code_edit(),

        // Navigation between lines
        KeyCode::Up | KeyCode::Char('k') => app.code_edit.move_up(),
        KeyCode::Down | KeyCode::Char('j') => app.code_edit.move_down(),

        // Edit current line
        KeyCode::Enter | KeyCode::Char('i') => app.begin_line_edit(),

        // Append new line after cursor
        KeyCode::Char('a') | KeyCode::Char('o') => {
            app.code_edit.append_line();
            app.begin_line_edit();
        }

        // Insert new line before cursor
        KeyCode::Char('O') => {
            app.code_edit.insert_line();
            app.begin_line_edit();
        }

        // Delete line (vim-style: d then d)
        KeyCode::Char('d') => {
            if app.code_edit.pending_d {
                app.code_edit.delete_line();
                app.code_edit.pending_d = false;
            } else {
                app.code_edit.pending_d = true;
            }
        }

        // Save
        KeyCode::Char('w') => { app.save_code_edit(); }

        _ => { app.code_edit.pending_d = false; }
    }
}

fn handle_line_edit(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Enter => app.commit_line_edit(),
        KeyCode::Esc => app.abort_line_edit(),
        KeyCode::Backspace => { app.code_edit.line_buf.pop(); }
        KeyCode::Char(c) => app.code_edit.line_buf.push(c),
        _ => {}
    }
}

fn handle_search(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            app.mode = AppMode::Browse;
            app.clear_search();
        }
        KeyCode::Enter => {
            app.mode = AppMode::Browse;
        }
        KeyCode::Backspace => {
            app.search.pop();
            app.apply_search();
        }
        KeyCode::Char(c) => {
            app.search.push(c);
            app.apply_search();
        }
        _ => {}
    }
}

fn handle_modal(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => app.cancel_modal(),
        KeyCode::Enter => {
            let mode = app.mode.clone();
            match mode {
                AppMode::RenameModal => { app.apply_rename(); }
                AppMode::FlagsModal => { app.apply_flags(); }
                _ => {}
            }
        }
        KeyCode::Backspace => {
            app.modal.buffer.pop();
            app.modal.error = None;
        }
        KeyCode::Char(c) => {
            app.modal.buffer.push(c);
            app.modal.error = None;
        }
        _ => {}
    }
}

/// External wrapper that handles the Quit action.
pub fn handle_events_with_quit(app: &mut App) -> anyhow::Result<Action> {
    if !event::poll(Duration::from_millis(100))? {
        return Ok(Action::Continue);
    }

    let ev = event::read()?;
    let Event::Key(key) = ev else { return Ok(Action::Continue) };
    if key.kind != KeyEventKind::Press {
        return Ok(Action::Continue);
    }

    // Check for quit before dispatching
    if app.mode == AppMode::Browse
        && (matches!(key.code, KeyCode::Char('q') | KeyCode::Char('Q'))
            || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL)))
    {
        return Ok(Action::Quit);
    }

    match &app.mode {
        AppMode::LineEdit => handle_line_edit(app, key.code),
        AppMode::CodeEdit => handle_code_edit(app, key.code),
        AppMode::Search => handle_search(app, key.code),
        AppMode::RenameModal | AppMode::FlagsModal => handle_modal(app, key.code),
        AppMode::Browse => handle_browse(app, key.code, key.modifiers),
    }

    Ok(Action::Continue)
}
