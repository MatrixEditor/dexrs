use std::collections::HashMap;
use std::path::PathBuf;

use dexrs::file::dump::StyledLine;

// -- Data types carried from the parsed DEX -----------------------------------

/// A fully-owned snapshot of a DEX class, pre-computed at startup.
#[derive(Clone)]
pub struct ClassEntry {
    pub descriptor: String,
    pub pretty_name: String,
    pub package: String,
    pub simple_name: String,
    pub access_flags: u32,
    /// Pretty-printed superclass name for display.
    pub superclass: String,
    /// Raw DEX superclass descriptor (e.g. `"Ljava/lang/Object;"`).
    pub superclass_desc: String,
    pub methods: Vec<MemberEntry>,
    pub fields: Vec<MemberEntry>,
}

#[derive(Clone)]
pub struct MemberEntry {
    /// Human-readable display name (with type/sig prefix).
    pub name: String,
    /// Raw method/field name without class prefix or type (e.g. `"<init>"`, `"counter"`).
    pub raw_name: String,
    /// For methods: full proto descriptor `"([Ljava/lang/String;)V"`.
    /// For fields: field type descriptor `"I"`, `"Ljava/lang/Object;"`.
    pub proto_or_type_desc: String,
    pub kind: MemberKind,
    pub access_flags: u32,
    /// File offset of the `code_item` in the DEX file.  0 = abstract/native (no code).
    /// Disassembly is computed on-demand from this offset and cached in `App::disasm_cache`.
    pub code_offset: u32,
    /// Code metadata summary (registers, ins, outs, tries).
    /// Fast to read — just 4 u16 fields from the code_item header.
    pub code_info: Option<String>,
}

impl MemberEntry {
    /// Extract registers/ins/outs from the code_info string.
    /// Format: "registers: N  ins: N  outs: N  tries: N"
    pub fn parse_registers(&self) -> (u16, u16, u16) {
        let Some(ref s) = self.code_info else { return (0, 0, 0) };
        fn extract(s: &str, key: &str) -> u16 {
            s.split(key)
                .nth(1)
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|n| n.parse().ok())
                .unwrap_or(0)
        }
        (extract(s, "registers: "), extract(s, "ins: "), extract(s, "outs: "))
    }
}

/// Cached disassembly for one method — computed lazily on first view.
pub struct DisasmEntry {
    /// Styled spans for the code viewer (PC -> highlighted tokens).
    pub styled: Vec<(u32, StyledLine)>,
    /// Assembler-compatible lines for the inline editor / rebuild pipeline.
    pub raw: Vec<String>,
}

/// Compute disassembly for a single `code_item` from raw DEX bytes.
/// Opens the DEX with `VerifyPreset::None` (pure pointer arithmetic, < 1 ms).
pub fn compute_disasm_from_bytes(bytes: &[u8], code_off: u32) -> DisasmEntry {
    if code_off == 0 || bytes.is_empty() {
        return DisasmEntry { styled: vec![], raw: vec![] };
    }
    use dexrs::file::{DexFile, DexLocation, verifier::VerifyPreset};
    let dex = match DexFile::open(&bytes, DexLocation::InMemory, VerifyPreset::None) {
        Ok(d) => d,
        Err(_) => return DisasmEntry { styled: vec![], raw: vec![] },
    };
    let ca = match dex.get_code_item_accessor(code_off) {
        Ok(c) => c,
        Err(_) => return DisasmEntry { styled: vec![], raw: vec![] },
    };
    let mut styled = Vec::new();
    let mut raw = Vec::new();
    let mut pc: u32 = 0;
    for insn in ca {
        let s = insn.to_styled(Some(&dex)).unwrap_or_else(|_| vec![dexrs::file::dump::Span {
            text: "<decode error>".to_string(),
            hl: dexrs::file::dump::Highlight::Plain,
        }]);
        let r = insn.to_assembler_text(&dex).unwrap_or_else(|_| "<decode error>".to_string());
        styled.push((pc, s));
        raw.push(r);
        pc += insn.size_in_code_units() as u32;
    }
    DisasmEntry { styled, raw }
}

#[derive(Clone, PartialEq)]
pub enum MemberKind {
    DirectMethod,
    VirtualMethod,
    StaticField,
    InstanceField,
}

impl MemberKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::DirectMethod | Self::VirtualMethod => "method",
            Self::StaticField => "static field",
            Self::InstanceField => "field",
        }
    }
    pub fn is_method(&self) -> bool {
        matches!(self, Self::DirectMethod | Self::VirtualMethod)
    }
}

// -- Tree ---------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum TreeItem {
    Package {
        name: String,    // "" = (no package)
        expanded: bool,
    },
    Class {
        class_idx: usize,
        expanded: bool,
    },
    Member {
        class_idx: usize,
        member_idx: usize, // index into class.methods + class.fields
    },
}

impl TreeItem {
    #[allow(dead_code)]
    pub fn indent(&self) -> u16 {
        match self {
            Self::Package { .. } => 0,
            Self::Class { .. } => 1,
            Self::Member { .. } => 2,
        }
    }
    #[allow(dead_code)]
    pub fn is_package(&self) -> bool { matches!(self, Self::Package { .. }) }
    #[allow(dead_code)]
    pub fn is_class(&self) -> bool { matches!(self, Self::Class { .. }) }
    #[allow(dead_code)]
    pub fn is_member(&self) -> bool { matches!(self, Self::Member { .. }) }
}

// -- App mode -----------------------------------------------------------------

#[derive(Clone, PartialEq)]
pub enum AppMode {
    /// Normal browsing
    Browse,
    /// Search bar open (filters tree)
    Search,
    /// In-TUI code editor for a method's instructions
    CodeEdit,
    /// Editing a single instruction line within CodeEdit
    LineEdit,
    /// Rename class modal
    RenameModal,
    /// Set access flags modal (class or member)
    FlagsModal,
}

/// Which panel has keyboard focus in Browse mode.
#[derive(Clone, PartialEq)]
pub enum Focus {
    Tree,
    Code,
}

// -- Inline code edit state ---------------------------------------------------

#[derive(Clone, Default)]
pub struct CodeEditState {
    /// Plain instruction lines (no PC prefix, no register header).
    pub lines: Vec<String>,
    /// Index of the highlighted line.
    pub cursor: usize,
    /// Scroll offset.
    pub scroll: u16,
    /// Per-line compile errors (after a failed save attempt).
    pub errors: HashMap<usize, String>,
    /// The class descriptor owning this method.
    pub class_desc: String,
    /// Full method name as stored in MemberEntry.name.
    pub method_name: String,
    /// (registers, ins, outs) from original code_info.
    pub registers: (u16, u16, u16),
    /// Dirty flag — true after any modification.
    pub dirty: bool,
    /// Buffer for the currently-edited line (LineEdit sub-mode).
    pub line_buf: String,
    /// Whether `dd` prefix was typed (delete-line detection).
    pub pending_d: bool,
}

impl CodeEditState {
    /// Number of visible lines.
    #[allow(dead_code)]
    pub fn len(&self) -> usize { self.lines.len() }

    /// Move cursor up.
    pub fn move_up(&mut self) {
        if self.cursor > 0 { self.cursor -= 1; }
        self.clamp_scroll();
        self.pending_d = false;
    }

    /// Move cursor down.
    pub fn move_down(&mut self) {
        if !self.lines.is_empty() && self.cursor + 1 < self.lines.len() {
            self.cursor += 1;
        }
        self.clamp_scroll();
        self.pending_d = false;
    }

    /// Insert a new (empty) line after the cursor.
    pub fn append_line(&mut self) {
        let pos = if self.lines.is_empty() { 0 } else { self.cursor + 1 };
        self.lines.insert(pos, String::new());
        self.cursor = pos;
        self.dirty = true;
        self.errors.clear();
    }

    /// Insert a new (empty) line before the cursor.
    pub fn insert_line(&mut self) {
        self.lines.insert(self.cursor, String::new());
        self.dirty = true;
        self.errors.clear();
    }

    /// Delete the current line.
    pub fn delete_line(&mut self) {
        if !self.lines.is_empty() {
            self.lines.remove(self.cursor);
            if self.cursor > 0 && self.cursor >= self.lines.len() {
                self.cursor = self.lines.len().saturating_sub(1);
            }
            self.dirty = true;
            self.errors.clear();
        }
    }

    /// Begin editing the current line: copy its text into line_buf.
    pub fn begin_line_edit(&mut self) {
        let text = self.lines.get(self.cursor).cloned().unwrap_or_default();
        self.line_buf = text;
    }

    /// Commit the edited line back.
    pub fn commit_line_edit(&mut self) {
        if let Some(line) = self.lines.get_mut(self.cursor) {
            *line = self.line_buf.clone();
        }
        self.line_buf.clear();
        self.dirty = true;
        self.errors.clear();
    }

    /// Abandon the current line edit.
    pub fn abort_line_edit(&mut self) {
        self.line_buf.clear();
    }

    /// Keep scroll so cursor is always visible.
    fn clamp_scroll(&mut self) {
        // Will be properly clamped in ui.rs after we know visible height.
        // Here we just ensure basic invariants.
        if (self.cursor as u16) < self.scroll {
            self.scroll = self.cursor as u16;
        }
    }

    /// Try to compile the current lines into a CodeDef.
    /// Returns the compiled code or an error string.
    pub fn compile(&self) -> Result<dexrs::file::CodeDef, String> {
        use dexrs::file::builder::CodeBuilder;
        let (regs, ins, outs) = self.registers;
        let mut cb = CodeBuilder::new(regs, ins, outs);
        for (i, line) in self.lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() { continue; }
            if let Some(lbl) = trimmed.strip_prefix(':') {
                cb.label(lbl);
            } else if let Err(e) = cb.emit(trimmed) {
                return Err(format!("line {}: {e}", i + 1));
            }
        }
        cb.build().map_err(|e| e.to_string())
    }
}

// -- Modal state ---------------------------------------------------------------

#[derive(Clone, Default)]
pub struct ModalState {
    pub buffer: String,
    pub error: Option<String>,
}

// -- Main App -----------------------------------------------------------------

pub struct App {
    // -- Source data ----------------------------------------------------------
    pub classes: Vec<ClassEntry>,
    /// Raw DEX bytes — always populated; used for lazy disassembly and edit mode.
    pub raw_bytes: Vec<u8>,
    /// Path to write the modified DEX file.  `Some` enables edit mode.
    pub output_path: Option<PathBuf>,
    pub file_info: String,
    /// On-demand disassembly cache: `(class_idx, member_idx)` -> styled + raw lines.
    pub disasm_cache: HashMap<(usize, usize), DisasmEntry>,

    // -- Tree state -----------------------------------------------------------
    /// Flat display list, rebuilt on expand/collapse or search.
    pub tree: Vec<TreeItem>,
    /// Cursor index in `tree`.
    pub tree_cursor: usize,
    /// Scroll offset for the tree pane.
    pub tree_scroll: usize,
    /// Per-package expansion (key = package name, "" = no-package group).
    pub pkg_expanded: HashMap<String, bool>,
    /// Per-class expansion state (key = class_idx).
    pub class_expanded: HashMap<usize, bool>,

    // -- Code pane ------------------------------------------------------------
    pub code_scroll: u16,
    pub code_total_lines: usize,
    pub code_visible_height: u16,

    // -- Focus & mode ---------------------------------------------------------
    pub focus: Focus,
    pub mode: AppMode,

    // -- Inline code edit -----------------------------------------------------
    pub code_edit: CodeEditState,

    // -- Modal (rename / flags) -----------------------------------------------
    pub modal: ModalState,

    // -- Search ---------------------------------------------------------------
    pub search: String,

    // -- Overlays -------------------------------------------------------------
    pub show_help: bool,
    pub show_info: bool,
}

impl App {
    pub fn new(classes: Vec<ClassEntry>, file_info: String, raw_bytes: Vec<u8>) -> Self {
        let n = classes.len();
        let mut app = App {
            classes,
            raw_bytes,
            output_path: None,
            file_info,
            disasm_cache: HashMap::new(),
            tree: Vec::new(),
            tree_cursor: 0,
            tree_scroll: 0,
            pkg_expanded: HashMap::new(),
            class_expanded: HashMap::new(),
            code_scroll: 0,
            code_total_lines: 0,
            code_visible_height: 0,
            focus: Focus::Tree,
            mode: AppMode::Browse,
            code_edit: CodeEditState::default(),
            modal: ModalState::default(),
            search: String::new(),
            show_help: false,
            show_info: false,
        };
        // All packages start expanded; no classes expanded by default.
        for (i, c) in app.classes.iter().enumerate() {
            app.pkg_expanded.entry(c.package.clone()).or_insert(true);
            app.class_expanded.insert(i, false);
        }
        // Expand first class so user sees something interesting immediately.
        if n > 0 {
            app.class_expanded.insert(0, true);
        }
        app.rebuild_tree();
        app
    }

    pub fn with_editable(mut self, output: Option<PathBuf>) -> Self {
        self.output_path = output;
        self
    }

    /// Returns true when edit mode is active (output path configured).
    pub fn is_editable(&self) -> bool {
        self.output_path.is_some()
    }

    /// Return the cached disassembly for `(class_idx, member_idx)`, computing it on first access.
    pub fn get_or_compute_disasm(&mut self, ci: usize, mi: usize) -> &DisasmEntry {
        let key = (ci, mi);
        if !self.disasm_cache.contains_key(&key) {
            let code_offset = {
                let cls = &self.classes[ci];
                if mi < cls.methods.len() {
                    cls.methods[mi].code_offset
                } else {
                    cls.fields[mi - cls.methods.len()].code_offset
                }
            };
            let entry = compute_disasm_from_bytes(&self.raw_bytes, code_offset);
            self.disasm_cache.insert(key, entry);
        }
        self.disasm_cache.get(&key).unwrap()
    }

    // -- Tree helpers ---------------------------------------------------------

    /// Rebuild the flat `tree` Vec from the current expansion state and search filter.
    pub fn rebuild_tree(&mut self) {
        self.tree.clear();
        let q = self.search.to_lowercase();

        // Group classes by package.
        let mut packages: Vec<String> = self.pkg_expanded.keys().cloned().collect();
        packages.sort();
        // Put no-package group first.
        if let Some(pos) = packages.iter().position(|p| p.is_empty()) {
            packages.remove(pos);
            packages.insert(0, String::new());
        }

        for pkg in &packages {
            // Collect matching class indices for this package.
            let class_indices: Vec<usize> = self
                .classes
                .iter()
                .enumerate()
                .filter(|(_, c)| &c.package == pkg)
                .filter(|(_, c)| {
                    q.is_empty()
                        || c.pretty_name.to_lowercase().contains(&q)
                        || c.descriptor.to_lowercase().contains(&q)
                })
                .map(|(i, _)| i)
                .collect();

            if class_indices.is_empty() {
                continue;
            }

            let expanded = *self.pkg_expanded.get(pkg).unwrap_or(&true);

            // Only show package header when there are multiple packages or a non-empty name.
            if !pkg.is_empty() {
                self.tree.push(TreeItem::Package {
                    name: pkg.clone(),
                    expanded,
                });
            }

            if expanded || pkg.is_empty() {
                for class_idx in class_indices {
                    let cls_expanded = *self.class_expanded.get(&class_idx).unwrap_or(&false);
                    self.tree.push(TreeItem::Class { class_idx, expanded: cls_expanded });
                    if cls_expanded {
                        let cls = &self.classes[class_idx];
                        for mi in 0..(cls.methods.len() + cls.fields.len()) {
                            self.tree.push(TreeItem::Member { class_idx, member_idx: mi });
                        }
                    }
                }
            }
        }

        // Clamp cursor to new length.
        if self.tree_cursor >= self.tree.len() && !self.tree.is_empty() {
            self.tree_cursor = self.tree.len() - 1;
        }
    }

    /// Toggle expansion of the tree item under the cursor.
    pub fn toggle_expand(&mut self) {
        if let Some(item) = self.tree.get(self.tree_cursor).cloned() {
            match item {
                TreeItem::Package { name, expanded } => {
                    self.pkg_expanded.insert(name, !expanded);
                    self.rebuild_tree();
                }
                TreeItem::Class { class_idx, expanded } => {
                    self.class_expanded.insert(class_idx, !expanded);
                    self.rebuild_tree();
                }
                TreeItem::Member { .. } => {
                    // Enter member: move focus to code pane.
                    self.focus = Focus::Code;
                    self.code_scroll = 0;
                }
            }
        }
    }

    /// Collapse the item under the cursor (or go to its parent).
    pub fn collapse_or_parent(&mut self) {
        if let Some(item) = self.tree.get(self.tree_cursor).cloned() {
            match item {
                TreeItem::Package { name, expanded: true } => {
                    self.pkg_expanded.insert(name, false);
                    self.rebuild_tree();
                }
                TreeItem::Class { class_idx, expanded: true } => {
                    self.class_expanded.insert(class_idx, false);
                    self.rebuild_tree();
                }
                TreeItem::Member { class_idx, .. } | TreeItem::Class { class_idx, .. } => {
                    // Navigate to the parent class/package.
                    let target_class = class_idx;
                    for (i, item) in self.tree.iter().enumerate() {
                        if let TreeItem::Class { class_idx, .. } = item {
                            if *class_idx == target_class {
                                self.tree_cursor = i;
                                self.clamp_tree_scroll();
                                return;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Move tree cursor up.
    pub fn tree_up(&mut self) {
        if self.tree_cursor > 0 {
            self.tree_cursor -= 1;
            self.clamp_tree_scroll();
        }
    }

    /// Move tree cursor down.
    pub fn tree_down(&mut self) {
        if self.tree_cursor + 1 < self.tree.len() {
            self.tree_cursor += 1;
            self.clamp_tree_scroll();
        }
    }

    fn clamp_tree_scroll(&mut self) {
        // Basic clamping; fine-tuned in ui.rs once we know visible_height.
        if self.tree_cursor < self.tree_scroll {
            self.tree_scroll = self.tree_cursor;
        }
    }

    // -- Current selection helpers ---------------------------------------------

    pub fn current_item(&self) -> Option<&TreeItem> {
        self.tree.get(self.tree_cursor)
    }

    /// Returns the ClassEntry for the currently focused tree item.
    pub fn current_class(&self) -> Option<&ClassEntry> {
        match self.current_item()? {
            TreeItem::Class { class_idx, .. } => self.classes.get(*class_idx),
            TreeItem::Member { class_idx, .. } => self.classes.get(*class_idx),
            TreeItem::Package { .. } => None,
        }
    }

    /// Returns (class_idx, member_idx) if cursor is on a Member item.
    pub fn current_member_indices(&self) -> Option<(usize, usize)> {
        match self.current_item()? {
            TreeItem::Member { class_idx, member_idx } => Some((*class_idx, *member_idx)),
            _ => None,
        }
    }

    /// Returns the MemberEntry for the currently focused tree item (if a member).
    pub fn current_member(&self) -> Option<&MemberEntry> {
        let (ci, mi) = self.current_member_indices()?;
        let cls = self.classes.get(ci)?;
        if mi < cls.methods.len() {
            cls.methods.get(mi)
        } else {
            cls.fields.get(mi - cls.methods.len())
        }
    }

    /// Returns the class index for the cursor position.
    pub fn current_class_idx(&self) -> Option<usize> {
        match self.current_item()? {
            TreeItem::Class { class_idx, .. } => Some(*class_idx),
            TreeItem::Member { class_idx, .. } => Some(*class_idx),
            _ => None,
        }
    }

    // -- Code pane helpers -----------------------------------------------------

    pub fn scroll_code_up(&mut self) {
        self.code_scroll = self.code_scroll.saturating_sub(1);
    }

    pub fn scroll_code_down(&mut self) {
        let max = (self.code_total_lines as u16).saturating_sub(self.code_visible_height);
        if self.code_scroll < max {
            self.code_scroll += 1;
        }
    }

    pub fn page_code_up(&mut self) {
        self.code_scroll = self.code_scroll.saturating_sub(self.code_visible_height.saturating_sub(1));
    }

    pub fn page_code_down(&mut self) {
        let max = (self.code_total_lines as u16).saturating_sub(self.code_visible_height);
        self.code_scroll = (self.code_scroll + self.code_visible_height.saturating_sub(1)).min(max);
    }

    // -- Search ---------------------------------------------------------------

    pub fn apply_search(&mut self) {
        self.tree_cursor = 0;
        self.tree_scroll = 0;
        self.rebuild_tree();
    }

    pub fn clear_search(&mut self) {
        self.search.clear();
        self.apply_search();
    }

    // -- Inline code edit -----------------------------------------------------

    /// Enter CodeEdit mode for the currently selected method.
    pub fn begin_code_edit(&mut self) -> bool {
        let (ci, mi) = match self.current_member_indices() {
            Some(x) => x,
            None => return false,
        };
        {
            let cls = &self.classes[ci];
            let member = if mi < cls.methods.len() {
                &cls.methods[mi]
            } else {
                &cls.fields[mi - cls.methods.len()]
            };
            if !member.kind.is_method() { return false; }
        }

        // Compute raw disasm (may be cached already from the viewer).
        let raw_lines = {
            let entry = self.get_or_compute_disasm(ci, mi);
            entry.raw.clone()
        };

        let cls = &self.classes[ci];
        let member = if mi < cls.methods.len() { &cls.methods[mi] } else { &cls.fields[mi - cls.methods.len()] };
        let registers = member.parse_registers();

        self.code_edit = CodeEditState {
            lines: raw_lines,
            cursor: 0,
            scroll: 0,
            errors: HashMap::new(),
            class_desc: cls.descriptor.clone(),
            method_name: member.name.clone(),
            registers,
            dirty: false,
            line_buf: String::new(),
            pending_d: false,
        };
        self.mode = AppMode::CodeEdit;
        true
    }

    /// Enter LineEdit for the line at code_edit.cursor.
    pub fn begin_line_edit(&mut self) {
        self.code_edit.begin_line_edit();
        self.mode = AppMode::LineEdit;
    }

    /// Commit the current line edit.
    pub fn commit_line_edit(&mut self) {
        self.code_edit.commit_line_edit();
        self.mode = AppMode::CodeEdit;
    }

    /// Abort line edit without changes.
    pub fn abort_line_edit(&mut self) {
        self.code_edit.abort_line_edit();
        self.mode = AppMode::CodeEdit;
    }

    /// Cancel the whole code edit session.
    pub fn cancel_code_edit(&mut self) {
        self.code_edit = CodeEditState::default();
        self.mode = AppMode::Browse;
    }

    /// Save the code edit: compile -> DexIr -> DexWriter -> update state.
    pub fn save_code_edit(&mut self) -> bool {
        let code_def = match self.code_edit.compile() {
            Ok(c) => c,
            Err(e) => {
                self.code_edit.errors.insert(self.code_edit.cursor, e);
                return false;
            }
        };
        if !self.is_editable() {
            self.code_edit.errors.insert(0, "Edit mode requires -o flag".into());
            return false;
        }

        // Rebuild DexIr from current class data, replacing the target method.
        let new_bytes = match rebuild_dex_with_new_code(
            &self.raw_bytes,
            &self.classes,
            &self.code_edit.class_desc,
            &self.code_edit.method_name,
            code_def,
        ) {
            Ok(b) => b,
            Err(e) => { self.code_edit.errors.insert(0, e); return false; }
        };

        // Write to output path if configured.
        if let Some(ref path) = self.output_path.clone() {
            if let Err(e) = std::fs::write(path, &new_bytes) {
                self.code_edit.errors.insert(0, format!("Write failed: {e}"));
                return false;
            }
        }

        // Refresh app state.
        match crate::commands::inspect::build_app_state_from_bytes(&new_bytes) {
            Ok((classes, file_info)) => {
                let prev_cursor = self.tree_cursor;
                self.classes = classes;
                self.file_info = file_info;
                self.raw_bytes = new_bytes;
                self.disasm_cache.clear(); // offsets changed after rewrite
                // Rebuild tree preserving expansion state.
                self.rebuild_tree();
                self.tree_cursor = prev_cursor.min(self.tree.len().saturating_sub(1));
                self.code_edit = CodeEditState::default();
                self.mode = AppMode::Browse;
                true
            }
            Err(e) => {
                self.raw_bytes = new_bytes;
                self.disasm_cache.clear();
                self.code_edit.errors.insert(0, format!("Re-parse: {e}"));
                false
            }
        }
    }

    // -- Modal helpers ---------------------------------------------------------

    pub fn begin_rename_modal(&mut self) {
        if self.current_class().is_none() { return; }
        self.modal = ModalState { buffer: String::new(), error: None };
        self.mode = AppMode::RenameModal;
    }

    pub fn begin_flags_modal(&mut self) {
        self.modal = ModalState { buffer: String::new(), error: None };
        self.mode = AppMode::FlagsModal;
    }

    pub fn cancel_modal(&mut self) {
        self.modal = ModalState::default();
        self.mode = AppMode::Browse;
    }

    pub fn apply_rename(&mut self) -> bool {
        let new_desc = self.modal.buffer.trim().to_string();
        if new_desc.is_empty() {
            self.modal.error = Some("Descriptor cannot be empty".into());
            return false;
        }
        let class_desc = match self.current_class() {
            Some(c) => c.descriptor.clone(),
            None => return false,
        };
        self.apply_editor_op(move |ed| ed.rename_class(&class_desc, &new_desc))
    }

    pub fn apply_flags(&mut self) -> bool {
        let val = match parse_flags_value(&self.modal.buffer) {
            Ok(v) => v,
            Err(e) => { self.modal.error = Some(e); return false; }
        };
        let is_member = self.current_member_indices().map(|(_, mi)| {
            let ci = self.current_class_idx().unwrap();
            let cls = &self.classes[ci];
            mi < cls.methods.len()
        }).unwrap_or(false);

        if is_member {
            let class_desc = self.current_class().map(|c| c.descriptor.clone()).unwrap_or_default();
            let method_name = self.current_member().map(|m| m.name.clone()).unwrap_or_default();
            self.apply_editor_op(move |ed| ed.set_method_access_flags(&class_desc, &method_name, val))
        } else {
            let class_desc = match self.current_class() {
                Some(c) => c.descriptor.clone(),
                None => return false,
            };
            self.apply_editor_op(move |ed| ed.set_class_access_flags(&class_desc, val))
        }
    }

    fn apply_editor_op<F>(&mut self, op: F) -> bool
    where F: FnOnce(&mut dexrs::file::DexEditor) -> dexrs::Result<()>
    {
        if self.raw_bytes.is_empty() {
            self.modal.error = Some("No source bytes".into());
            return false;
        }
        let mut editor = match dexrs::file::DexEditor::from_bytes(self.raw_bytes.clone()) {
            Ok(e) => e,
            Err(e) => { self.modal.error = Some(format!("DexEditor: {e}")); return false; }
        };
        if let Err(e) = op(&mut editor) {
            self.modal.error = Some(format!("Edit failed: {e}"));
            return false;
        }
        let new_bytes = match editor.build() {
            Ok(b) => b,
            Err(e) => { self.modal.error = Some(format!("Build failed: {e}")); return false; }
        };
        if let Some(ref path) = self.output_path.clone() {
            if let Err(e) = std::fs::write(path, &new_bytes) {
                self.modal.error = Some(format!("Write failed: {e}"));
                return false;
            }
        }
        match crate::commands::inspect::build_app_state_from_bytes(&new_bytes) {
            Ok((classes, file_info)) => {
                let prev = self.tree_cursor;
                self.classes = classes;
                self.file_info = file_info;
                self.raw_bytes = new_bytes;
                self.disasm_cache.clear();
                self.rebuild_tree();
                self.tree_cursor = prev.min(self.tree.len().saturating_sub(1));
                self.modal = ModalState::default();
                self.mode = AppMode::Browse;
                true
            }
            Err(e) => {
                self.raw_bytes = new_bytes;
                self.disasm_cache.clear();
                self.modal.error = Some(format!("Re-parse: {e}"));
                false
            }
        }
    }
}

// -- ClassEntry -> DexIr + target method override ------------------------------

fn rebuild_dex_with_new_code(
    raw_bytes: &[u8],
    classes: &[ClassEntry],
    target_class: &str,
    target_method: &str,
    new_code: dexrs::file::CodeDef,
) -> Result<Vec<u8>, String> {
    use dexrs::file::{
        builder::CodeBuilder,
        ir::{ClassDef, FieldDef, MethodDef, ProtoKey},
        DexFile, DexIr, DexLocation, DexWriter,
        verifier::VerifyPreset,
    };

    // Re-open the original DEX so we can re-assemble non-target methods from bytes.
    let dex = DexFile::open(&raw_bytes, DexLocation::InMemory, VerifyPreset::None)
        .map_err(|e| e.to_string())?;

    let mut ir = DexIr::new(35);

    for ce in classes {
        let mut cls = ClassDef::new(&ce.descriptor);
        cls.access_flags = ce.access_flags;
        if !ce.superclass_desc.is_empty() {
            cls.superclass = Some(ce.superclass_desc.clone());
        }

        for m in &ce.methods {
            let proto = match ProtoKey::from_descriptor(&m.proto_or_type_desc) {
                Some(p) => p,
                None => ProtoKey { return_type: "V".into(), params: vec![] },
            };

            let is_target = ce.descriptor == target_class && m.raw_name == target_method;

            let code = if is_target {
                Some(new_code.clone())
            } else if m.code_offset == 0 {
                None
            } else {
                // Re-assemble the original code from the raw bytes.
                let ca = match dex.get_code_item_accessor(m.code_offset) {
                    Ok(c) => c,
                    Err(_) => { continue; }
                };
                let regs = ca.registers_size();
                let ins = ca.ins_size();
                let outs = ca.outs_size();
                let mut cb = CodeBuilder::new(regs, ins, outs);
                let mut ok = true;
                for insn in ca {
                    match insn.to_assembler_text(&dex) {
                        Ok(text) => {
                            let t = text.trim().to_string();
                            if t.is_empty() { continue; }
                            if let Some(lbl) = t.strip_prefix(':') {
                                cb.label(lbl);
                            } else if cb.emit(&t).is_err() {
                                ok = false;
                                break;
                            }
                        }
                        Err(_) => { ok = false; break; }
                    }
                }
                if ok { cb.build().ok() } else { None }
            };

            let mut method = MethodDef::new(&m.raw_name, proto);
            method.access_flags = m.access_flags;
            if let Some(c) = code { method.code = Some(c); }

            if matches!(m.kind, MemberKind::DirectMethod) {
                cls.direct_methods.push(method);
            } else {
                cls.virtual_methods.push(method);
            }
        }

        for f in &ce.fields {
            let mut fd = FieldDef::new(&f.raw_name, &f.proto_or_type_desc);
            fd.access_flags = f.access_flags;
            if matches!(f.kind, MemberKind::StaticField) {
                cls.static_fields.push(fd);
            } else {
                cls.instance_fields.push(fd);
            }
        }

        ir.add_class(cls);
    }

    DexWriter::write(ir).map_err(|e| e.to_string())
}

// -- Misc helpers -------------------------------------------------------------

fn parse_flags_value(s: &str) -> Result<u32, String> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).map_err(|e| format!("invalid hex: {e}"))
    } else {
        s.parse::<u32>().map_err(|e| format!("invalid number: {e}"))
    }
}
