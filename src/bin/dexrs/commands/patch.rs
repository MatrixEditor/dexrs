use anyhow::{Context, Result};

use crate::cli::{PatchFlagsArgs, PatchInsnArgs};

fn parse_int(s: &str) -> Result<u32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).context("invalid hex value")
    } else {
        s.parse::<u32>().context("invalid decimal value")
    }
}

/// `patch flags` - in-place: set class access flags, then update checksum.
///
/// Uses `DexEditor` for class lookup; writes the result back to the same file.
pub fn run_flags(args: &PatchFlagsArgs) -> Result<()> {
    let flags = parse_int(&args.flags).context("--flags")?;

    let mut editor = dexrs::file::DexEditor::from_file(&args.file)
        .with_context(|| format!("cannot open '{}'", args.file.display()))?;
    editor
        .set_class_access_flags(&args.class, flags)
        .context("patch flags")?;
    editor
        .write_to(&args.file)
        .with_context(|| format!("cannot write '{}'", args.file.display()))?;

    eprintln!("patched (in-place): {}", args.file.display());
    Ok(())
}

/// `patch insn` - in-place: overwrite one instruction word, then update checksum.
pub fn run_insn(args: &PatchInsnArgs) -> Result<()> {
    let code_off = parse_int(&args.code_offset).context("--code-offset")?;
    let word = parse_int(&args.word).context("--word")? as u16;

    let mut data = std::fs::read(&args.file)
        .with_context(|| format!("cannot read '{}'", args.file.display()))?;
    dexrs::file::patch_instruction_word(&mut data, code_off, args.pc, word)?;
    dexrs::file::update_checksum(&mut data);
    std::fs::write(&args.file, &data)
        .with_context(|| format!("cannot write '{}'", args.file.display()))?;

    eprintln!("patched (in-place): {}", args.file.display());
    Ok(())
}
