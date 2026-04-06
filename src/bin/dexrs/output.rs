use comfy_table::{presets::UTF8_BORDERS_ONLY, Cell, Color, Table};
use crossterm::style::Stylize;

pub struct Printer {
    pub json: bool,
    pub color: bool,
}

impl Printer {
    pub fn new(json: bool, no_color: bool) -> Self {
        Self { json, color: !no_color }
    }

    pub fn table(&self, headers: &[&str], rows: Vec<Vec<String>>) {
        let mut table = Table::new();
        table.load_preset(UTF8_BORDERS_ONLY);

        let header_cells: Vec<Cell> = headers
            .iter()
            .map(|h| {
                if self.color {
                    Cell::new(h).fg(Color::Cyan)
                } else {
                    Cell::new(h)
                }
            })
            .collect();
        table.set_header(header_cells);

        for row in rows {
            table.add_row(row);
        }

        println!("{table}");
    }

    pub fn section(&self, title: &str) {
        if self.color {
            println!("\n{}", title.bold().yellow());
        } else {
            println!("\n{title}");
        }
    }

    pub fn kv(&self, key: &str, value: &str) {
        if self.color {
            println!("  {:<20} {value}", key.cyan());
        } else {
            println!("  {key:<20} {value}");
        }
    }

    pub fn item(&self, value: &str) {
        println!("  {value}");
    }

    #[allow(dead_code)]
    pub fn info(&self, msg: &str) {
        if self.color {
            eprintln!("{}", msg.dim());
        } else {
            eprintln!("{msg}");
        }
    }

    pub fn error(&self, msg: &str) {
        if self.color {
            eprintln!("{} {msg}", "error:".red().bold());
        } else {
            eprintln!("error: {msg}");
        }
    }
}

/// Format a DEX type descriptor into a human-readable Java-style name.
pub fn pretty_type(desc: &str) -> String {
    dexrs::desc_names::pretty_desc(desc)
}

/// Format access flags bitmask into a string like "public static final".
pub fn format_flags(flags: u32) -> String {
    use dexrs::file::*;
    let mut parts = Vec::new();
    if flags & ACC_PUBLIC != 0    { parts.push("public"); }
    if flags & ACC_PRIVATE != 0   { parts.push("private"); }
    if flags & ACC_PROTECTED != 0 { parts.push("protected"); }
    if flags & ACC_STATIC != 0    { parts.push("static"); }
    if flags & ACC_FINAL != 0     { parts.push("final"); }
    if flags & ACC_SYNCHRONIZED != 0 { parts.push("synchronized"); }
    if flags & ACC_NATIVE != 0    { parts.push("native"); }
    if flags & ACC_ABSTRACT != 0  { parts.push("abstract"); }
    if flags & ACC_STRICT != 0    { parts.push("strictfp"); }
    if flags & ACC_INTERFACE != 0 { parts.push("interface"); }
    if flags & ACC_ENUM != 0      { parts.push("enum"); }
    if flags & ACC_ANNOTATION != 0 { parts.push("@interface"); }
    if flags & ACC_SYNTHETIC != 0 { parts.push("synthetic"); }
    if flags & ACC_CONSTRUCTOR != 0 { parts.push("constructor"); }
    parts.join(" ")
}

/// Normalise a user-supplied class name to a DEX descriptor.
/// Accepts "com.example.Foo", "Lcom/example/Foo;", or "com/example/Foo".
pub fn to_descriptor(name: &str) -> String {
    if name.starts_with('L') && name.ends_with(';') {
        return name.to_owned();
    }
    let inner = name.replace('.', "/");
    format!("L{inner};")
}
