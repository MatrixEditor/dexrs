//! Demonstrates DEX file modification using `DexEditor` (Tier 2 API) and
//! the low-level `update_checksum` helper (Tier 1).
//!
//! Run with:
//! ```
//! cargo run --example dex_edit -- path/to/classes.dex
//! ```

use std::{env, fs, path::Path};

use dexrs::file::{patch::update_checksum, DexEditor};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| "classes.dex".to_string());

    example_set_flags(&path, "/tmp/out_flags.dex")?;
    example_rename_class(&path, "/tmp/out_renamed.dex")?;
    example_method_flags(&path, "/tmp/out_method.dex")?;
    example_manual_checksum(&path)?;

    Ok(())
}

/// Change class access flags via name lookup.
fn example_set_flags(src: &str, out: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut editor = DexEditor::from_file(Path::new(src))?;

    // Accepts dotted ("com.example.Foo"), slash ("com/example/Foo"),
    // or descriptor ("Lcom/example/Foo;") form.
    editor.set_class_access_flags("LMain;", 0x0011 /* public final */)?;

    // Strip hidden-API restriction metadata (no-op if section is absent).
    let _ = editor.clear_hiddenapi_flags();

    // build() recalculates the Adler32 checksum and returns the final bytes.
    let bytes = editor.build()?;
    fs::write(out, &bytes)?;
    println!("set_flags  -> {out}");
    Ok(())
}

/// Rename a class and every cross-reference in the string pool.
fn example_rename_class(src: &str, out: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut editor = DexEditor::from_file(Path::new(src))?;

    // Same MUTF-8 byte length  -> in-place patch + sort fixup.
    // Different byte length    -> full string-pool rebuild + offset adjustment.
    editor.rename_class("LMain;", "LRenamedMain;")?;

    // write_to() combines build() + fs::write in one call.
    editor.write_to(Path::new(out))?;
    println!("rename     -> {out}");
    Ok(())
}

/// Change access flags on a specific method inside a class.
fn example_method_flags(src: &str, out: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut editor = DexEditor::from_file(Path::new(src))?;

    // LEB128 re-encoding is handled automatically when the encoded width changes.
    editor.set_method_access_flags("LMain;", "main", 0x0009 /* public static */)?;

    editor.write_to(Path::new(out))?;
    println!("method flags -> {out}");
    Ok(())
}

/// Low-level: manually patch raw bytes, then fix the checksum.
fn example_manual_checksum(src: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = fs::read(src)?;

    // DEX header layout (bytes):
    //   0–7   magic ("dex\n035\0")
    //   8–11  Adler32 checksum  ← recalculated by update_checksum
    //   12–31 SHA-1 signature   (not updated here)
    //   32–35 file_size
    //   ...
    //   100–103 class_defs_off

    // Example: zero out byte 200 (arbitrary mutation for illustration).
    if buf.len() > 200 {
        buf[200] = 0;
    }

    // Always call update_checksum after raw mutations to keep the file valid.
    update_checksum(&mut buf);
    println!("manual patch checksum OK, file_size={}", buf.len());
    Ok(())
}
