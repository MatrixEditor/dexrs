use std::fs::File;
#[cfg(feature = "vdex")]
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
#[cfg(feature = "vdex")]
use anyhow::bail;
use crossterm::{
    event::{self, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use dexrs::file::{dump::prettify, verifier::VerifyPreset, DexContainer, DexFile, DexFileContainer, DexLocation};
#[cfg(feature = "vdex")]
use dexrs::vdex::VdexFileContainer;
use ratatui::{backend::CrosstermBackend, Terminal};
#[cfg(feature = "vdex")]
use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::{
    cli::InspectArgs,
    tui::{
        app::{App, ClassEntry, MemberEntry, MemberKind},
        events::{handle_events_with_quit, Action},
        ui::{draw, draw_loading},
    },
};

pub fn run(args: &InspectArgs) -> Result<()> {
    let file = File::open(&args.file)
        .map_err(|e| anyhow::anyhow!("cannot open '{}': {e}", args.file.display()))?;
    let container = DexFileContainer::new(&file).verify(!args.no_verify);
    let dex = container.open()?;

    let total_classes = dex.num_class_defs() as usize;
    let file_name = args.file.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("(unknown)")
        .to_string();

    // Enter TUI mode early so we can show a loading screen.
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Shared atomic progress counter updated by the build thread.
    let progress = Arc::new(AtomicUsize::new(0));
    let progress_clone = Arc::clone(&progress);

    // Cancel flag: set by the loading UI loop when the user presses Esc / Ctrl+C.
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_build = Arc::clone(&cancel);

    // Run build_app_state in a scoped thread so it can borrow `dex`.
    let build_result: anyhow::Result<Option<(Vec<ClassEntry>, String)>> =
        std::thread::scope(|s| {
            let handle = s.spawn(|| {
                build_app_state(&dex, &cancel_build, |current, _total| {
                    progress_clone.store(current, Ordering::Relaxed);
                })
            });

            // Render loading frames; poll for Esc / Ctrl+C to cancel.
            let mut tick: u64 = 0;
            loop {
                let current = progress.load(Ordering::Relaxed);
                terminal
                    .draw(|f| draw_loading(f, &file_name, current, total_classes, tick))?;

                // Drain all pending key events.
                while event::poll(Duration::ZERO)? {
                    if let event::Event::Key(key) = event::read()? {
                        match key.code {
                            KeyCode::Esc | KeyCode::Char('q') => {
                                cancel.store(true, Ordering::Relaxed);
                            }
                            KeyCode::Char('c')
                                if key.modifiers.contains(KeyModifiers::CONTROL) =>
                            {
                                cancel.store(true, Ordering::Relaxed);
                            }
                            _ => {}
                        }
                    }
                }

                if handle.is_finished() {
                    break;
                }

                std::thread::sleep(Duration::from_millis(40));
                tick = tick.wrapping_add(1);
            }

            handle
                .join()
                .map_err(|_| anyhow::anyhow!("build thread panicked"))?
        });

    // Drop the mmap handles — all data is now owned by classes/file_info.
    drop(dex);
    drop(container);
    drop(file);

    match build_result {
        Err(e) => {
            let _ = disable_raw_mode();
            let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
            Err(e)
        }
        Ok(None) => {
            // User cancelled loading — restore terminal and exit cleanly.
            disable_raw_mode()?;
            execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
            Ok(())
        }
        Ok(Some((classes, file_info))) => {
            // Re-read bytes for lazy disassembly (OS page cache makes this fast).
            let raw_bytes = std::fs::read(&args.file)
                .map_err(|e| anyhow::anyhow!("cannot read '{}': {e}", args.file.display()))
                .inspect_err(|_| {
                    let _ = disable_raw_mode();
                    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
                })?;
            let app = App::new(classes, file_info, raw_bytes);
            let app = app.with_editable(args.output.clone());
            run_tui_with_terminal(app, terminal)
        }
    }
}

pub fn build_app_state<'a, C: DexContainer<'a>>(
    dex: &DexFile<'a, C>,
    cancel: &AtomicBool,
    progress: impl Fn(usize, usize),
) -> Result<Option<(Vec<ClassEntry>, String)>> {
    let h = dex.get_header();
    let file_info = format!(
        "Format:   {}\nVersion:  {}\nFile:     {} bytes\nClasses:  {}\nMethods:  {}\nStrings:  {}",
        if dex.is_compact_dex() { "Compact DEX" } else { "Standard DEX" },
        h.get_version(),
        h.file_size,
        h.class_defs_size,
        h.method_ids_size,
        h.string_ids_size,
    );

    let total = dex.num_class_defs() as usize;
    let mut classes = Vec::with_capacity(total);

    for idx in 0..dex.num_class_defs() {
        // Check for user-initiated cancel before each class.
        if cancel.load(Ordering::Relaxed) {
            return Ok(None);
        }
        progress(idx as usize, total);
        let cd = match dex.get_class_def(idx) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let descriptor = dex.get_class_desc_utf16_lossy(cd).unwrap_or_default();
        let pretty_name = dexrs::desc_names::pretty_desc(&descriptor);

        let (package, simple_name) = split_class_name(&pretty_name);

        let superclass_desc = if cd.superclass_idx != u16::MAX {
            dex.get_type_desc_utf16_lossy_at(cd.superclass_idx).unwrap_or_default()
        } else {
            String::new()
        };
        let superclass = if superclass_desc.is_empty() {
            String::new()
        } else {
            dexrs::desc_names::pretty_desc(&superclass_desc)
        };

        let mut methods: Vec<MemberEntry> = Vec::new();
        let mut fields: Vec<MemberEntry> = Vec::new();

        if let Ok(Some(acc)) = dex.get_class_accessor(cd) {
            if let Ok(all_methods) = acc.get_methods() {
                for m in all_methods {
                    let name = dex.pretty_method_at(m.index, prettify::Method::WithSig);
                    let kind = if m.is_static_or_direct {
                        MemberKind::DirectMethod
                    } else {
                        MemberKind::VirtualMethod
                    };
                    let (raw_name, proto_or_type_desc) = dex
                        .get_method_id(m.index)
                        .ok()
                        .and_then(|mid| {
                            let raw = dex.get_str_lossy_at(mid.name_idx).ok()?;
                            let proto = dex.get_proto_id(mid.proto_idx).ok()?;
                            let ret = dex.get_type_desc_utf16_lossy_at(proto.return_type_idx).ok()?;
                            let mut desc = String::from("(");
                            if let Ok(Some(params)) = dex.get_type_list(proto.parameters_off) {
                                for tp in params {
                                    desc.push_str(&dex.get_type_desc_utf16_lossy_at(tp.type_idx).unwrap_or_default());
                                }
                            }
                            desc.push(')');
                            desc.push_str(&ret);
                            Some((raw, desc))
                        })
                        .unwrap_or_else(|| (name.clone(), "()V".to_string()));
                    // Only read the code_item header (4 × u16) — no instruction scanning.
                    let code_info = build_code_info(dex, m.code_offset);
                    methods.push(MemberEntry {
                        name,
                        raw_name,
                        proto_or_type_desc,
                        kind,
                        access_flags: m.access_flags,
                        code_offset: m.code_offset,
                        code_info,
                    });
                }
            }

            for f in acc.get_fields() {
                let name = dex.pretty_field_at(f.index, prettify::Field::WithType);
                let kind = if f.is_static {
                    MemberKind::StaticField
                } else {
                    MemberKind::InstanceField
                };
                let (raw_name, proto_or_type_desc) = dex
                    .get_field_id(f.index)
                    .ok()
                    .and_then(|fid| {
                        let raw = dex.get_str_lossy(dex.get_string_id(fid.name_idx).ok()?).ok()?;
                        let ftype = dex.get_type_desc_utf16_lossy_at(fid.type_idx).ok()?;
                        Some((raw, ftype))
                    })
                    .unwrap_or_else(|| (name.clone(), "Ljava/lang/Object;".to_string()));
                fields.push(MemberEntry {
                    name,
                    raw_name,
                    proto_or_type_desc,
                    kind,
                    access_flags: f.access_flags,
                    code_offset: 0,
                    code_info: None,
                });
            }
        }

        classes.push(ClassEntry {
            descriptor,
            pretty_name,
            package,
            simple_name,
            access_flags: cd.access_flags,
            superclass,
            superclass_desc,
            methods,
            fields,
        });
    }

    Ok(Some((classes, file_info)))
}

/// Fast code-item header read: registers, ins, outs, tries — zero instruction scanning.
fn build_code_info<'a, C: DexContainer<'a>>(dex: &DexFile<'a, C>, code_off: u32) -> Option<String> {
    if code_off == 0 { return None; }
    let ca = dex.get_code_item_accessor(code_off).ok()?;
    Some(format!(
        "registers: {}  ins: {}  outs: {}  tries: {}",
        ca.registers_size(),
        ca.ins_size(),
        ca.outs_size(),
        ca.tries_size(),
    ))
}

fn split_class_name(pretty: &str) -> (String, String) {
    if let Some(pos) = pretty.rfind('.') {
        (pretty[..pos].to_string(), pretty[pos + 1..].to_string())
    } else {
        (String::new(), pretty.to_string())
    }
}

/// Re-parse raw DEX bytes into `(classes, file_info)` for live refresh after edits.
pub fn build_app_state_from_bytes(bytes: &[u8]) -> anyhow::Result<(Vec<ClassEntry>, String)> {
    let cancel = AtomicBool::new(false);
    let dex = DexFile::open(&bytes, DexLocation::InMemory, VerifyPreset::None)?;
    build_app_state(&dex, &cancel, |_, _| {})?
        .ok_or_else(|| anyhow::anyhow!("cancelled"))
}

fn run_tui_with_terminal(
    mut app: App,
    mut terminal: Terminal<CrosstermBackend<std::io::Stdout>>,
) -> Result<()> {
    let result = run_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    loop {
        terminal.draw(|f| draw(f, app))?;

        match handle_events_with_quit(app)? {
            Action::Quit => break,
            Action::Continue => {}
        }
    }
    Ok(())
}

// -- VDEX inspect --------------------------------------------------------------

/// Open a VDEX file and launch the TUI inspector on one of its embedded DEX
/// files.  When `dex_index` is `None` and the VDEX contains more than one DEX,
/// a small interactive picker is shown first.
#[cfg(feature = "vdex")]
pub fn run_vdex_inspect(
    path: &std::path::Path,
    dex_index: Option<u32>,
    output: Option<PathBuf>,
) -> Result<()> {
    let file =
        File::open(path).map_err(|e| anyhow::anyhow!("cannot open '{}': {e}", path.display()))?;
    let container = VdexFileContainer::new(&file);
    let vdex = container.open()?;

    let n = vdex.num_dex_files();
    if n == 0 {
        bail!("VDEX file contains no embedded DEX files");
    }
    if !vdex.has_dex_section() {
        bail!("VDEX file does not contain a DEX file section");
    }

    // Determine which DEX index to open (or pick interactively).
    let chosen: u32 = match dex_index {
        Some(i) => {
            if i >= n {
                bail!("DEX index {i} is out of range (0..{n})");
            }
            i
        }
        None if n == 1 => 0,
        None => {
            // Build a label list of "DEX[i]  checksum=0x…  size=… bytes"
            let labels: Vec<String> = (0..n)
                .map(|i| {
                    let cs = vdex.dex_checksum_at(i).unwrap_or(0);
                    let sz = vdex.get_dex_file_data(i).map(|d| d.len()).unwrap_or(0);
                    format!("DEX[{i}]   checksum={cs:#010x}   size={sz} bytes")
                })
                .collect();

            pick_dex_interactively(&labels)?
        }
    };

    // Extract the raw DEX bytes — must be copied because the mmap/container
    // lifetime ends when this function returns and App owns its bytes.
    let dex_bytes = vdex.get_dex_file_data(chosen)?.to_vec();
    drop(vdex);
    drop(container);
    drop(file);

    // Re-use the normal DEX inspect flow with the in-memory bytes.
    run_with_bytes(dex_bytes, output)
}

/// Show an interactive VDEX DEX-file picker and return the chosen index.
#[cfg(feature = "vdex")]
fn pick_dex_interactively(labels: &[String]) -> Result<u32> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut selected: usize = 0;
    let mut list_state = ListState::default();
    list_state.select(Some(0));

    let result = loop {
        terminal.draw(|f| draw_vdex_picker(f, labels, &mut list_state))?;

        if event::poll(Duration::from_millis(50))? {
            if let event::Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        if selected > 0 {
                            selected -= 1;
                            list_state.select(Some(selected));
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if selected + 1 < labels.len() {
                            selected += 1;
                            list_state.select(Some(selected));
                        }
                    }
                    KeyCode::Enter => break Ok(selected as u32),
                    KeyCode::Esc
                    | KeyCode::Char('q')
                    | KeyCode::Char('c')
                        if key.modifiers.contains(KeyModifiers::CONTROL) =>
                    {
                        break Err(anyhow::anyhow!("cancelled"))
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        break Err(anyhow::anyhow!("cancelled"))
                    }
                    _ => {}
                }
            }
        }
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    result
}

#[cfg(feature = "vdex")]
fn draw_vdex_picker(f: &mut Frame, labels: &[String], state: &mut ListState) {
    let area = f.area();
    let [header_area, list_area, footer_area] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(area);

    let title = Paragraph::new(Line::from(vec![
        Span::styled("VDEX  ", Style::default().fg(Color::Rgb(190, 160, 90))),
        Span::styled(
            "Select an embedded DEX file to inspect",
            Style::default().fg(Color::Rgb(200, 200, 200)),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, header_area);

    let items: Vec<ListItem> = labels
        .iter()
        .map(|l| ListItem::new(l.as_str()))
        .collect();
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("DEX Files"))
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(42, 48, 58))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, list_area, state);

    let hint = Paragraph::new(
        "  ↑/↓ navigate   Enter select   q/Esc cancel",
    )
    .style(Style::default().fg(Color::Rgb(100, 110, 120)));
    f.render_widget(hint, footer_area);
}

/// Run the full TUI inspector using a pre-loaded byte buffer instead of a file.
#[cfg(feature = "vdex")]
fn run_with_bytes(dex_bytes: Vec<u8>, output: Option<PathBuf>) -> Result<()> {
    let dex = DexFile::open(&dex_bytes, DexLocation::InMemory, VerifyPreset::None)?;
    let total_classes = dex.num_class_defs() as usize;
    let file_name = "(embedded DEX)".to_string();

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let progress = Arc::new(AtomicUsize::new(0));
    let progress_clone = Arc::clone(&progress);
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_build = Arc::clone(&cancel);

    let build_result: anyhow::Result<Option<(Vec<ClassEntry>, String)>> =
        std::thread::scope(|s| {
            let handle = s.spawn(|| {
                build_app_state(&dex, &cancel_build, |current, _total| {
                    progress_clone.store(current, Ordering::Relaxed);
                })
            });

            let mut tick: u64 = 0;
            loop {
                let current = progress.load(Ordering::Relaxed);
                terminal.draw(|f| draw_loading(f, &file_name, current, total_classes, tick))?;

                while event::poll(Duration::ZERO)? {
                    if let event::Event::Key(key) = event::read()? {
                        match key.code {
                            KeyCode::Esc | KeyCode::Char('q') => {
                                cancel.store(true, Ordering::Relaxed);
                            }
                            KeyCode::Char('c')
                                if key.modifiers.contains(KeyModifiers::CONTROL) =>
                            {
                                cancel.store(true, Ordering::Relaxed);
                            }
                            _ => {}
                        }
                    }
                }

                if handle.is_finished() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(40));
                tick = tick.wrapping_add(1);
            }

            handle.join().map_err(|_| anyhow::anyhow!("build thread panicked"))?
        });

    drop(dex);

    match build_result {
        Err(e) => {
            let _ = disable_raw_mode();
            let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
            Err(e)
        }
        Ok(None) => {
            disable_raw_mode()?;
            execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
            Ok(())
        }
        Ok(Some((classes, file_info))) => {
            let app = App::new(classes, file_info, dex_bytes).with_editable(output);
            run_tui_with_terminal(app, terminal)
        }
    }
}
