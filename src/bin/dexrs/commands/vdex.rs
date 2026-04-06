//! CLI handlers for VDEX file operations.
//!
//! Subcommands:
//! - `vdex info`    - show header, sections and checksums
//! - `vdex list`    - tabular list of all embedded DEX files
//! - `vdex extract` - write a single embedded DEX to disk
//! - `vdex inspect` - launch the TUI inspector on an embedded DEX

use std::fs::File;

use anyhow::{bail, Context, Result};
use serde_json::json;

use dexrs::vdex::{VdexFileContainer, VdexSection};

use crate::{
    cli::{VdexExtractArgs, VdexInfoArgs, VdexListArgs},
    output::Printer,
};
#[cfg(feature = "tui")]
use crate::cli::VdexInspectArgs;
#[cfg(feature = "tui")]
use crate::commands::inspect::run_vdex_inspect;

// -- info ----------------------------------------------------------------------

pub fn run_info(args: &VdexInfoArgs) -> Result<()> {
    let file = File::open(&args.file)
        .with_context(|| format!("cannot open '{}'", args.file.display()))?;
    let container = VdexFileContainer::new(&file);
    let vdex = container.open()?;

    let p = Printer::new(args.json, args.no_color);
    let h = vdex.file_header();
    let version = String::from_utf8_lossy(&h.vdex_version)
        .trim_end_matches('\0')
        .to_string();

    let checksums: Vec<String> = vdex
        .dex_checksums()
        .iter()
        .map(|c| format!("{c:#010x}"))
        .collect();

    if p.json {
        let sections: Vec<_> = (0..vdex.num_sections())
            .filter_map(|i| {
                let kind = match i {
                    0 => VdexSection::Checksum,
                    1 => VdexSection::DexFile,
                    2 => VdexSection::VerifierDeps,
                    3 => VdexSection::TypeLookupTable,
                    _ => return None,
                };
                let sh = vdex.get_section_header(kind)?;
                Some(json!({
                    "kind": i,
                    "offset": sh.section_offset,
                    "size": sh.section_size,
                }))
            })
            .collect();

        println!(
            "{}",
            json!({
                "magic": String::from_utf8_lossy(&h.magic),
                "version": version,
                "num_sections": h.number_of_sections,
                "num_dex_files": vdex.num_dex_files(),
                "has_dex_section": vdex.has_dex_section(),
                "checksums": checksums,
                "sections": sections,
            })
        );
        return Ok(());
    }

    p.section("VDEX File");
    p.kv("Magic:", &String::from_utf8_lossy(&h.magic));
    p.kv("Version:", &version);
    p.kv("Sections:", &h.number_of_sections.to_string());
    p.kv("Embedded DEX files:", &vdex.num_dex_files().to_string());
    p.kv("Has DEX section:", &vdex.has_dex_section().to_string());

    p.section("Sections");
    for i in 0..vdex.num_sections() {
        let kind = match i {
            0 => VdexSection::Checksum,
            1 => VdexSection::DexFile,
            2 => VdexSection::VerifierDeps,
            3 => VdexSection::TypeLookupTable,
            _ => break,
        };
        if let Some(sh) = vdex.get_section_header(kind) {
            let name = format!("[{i}] {kind:?}");
            let val = if sh.section_size == 0 {
                "(absent)".to_string()
            } else {
                format!("{} bytes @ {:#x}", sh.section_size, sh.section_offset)
            };
            p.kv(&name, &val);
        }
    }

    if !checksums.is_empty() {
        p.section("DEX Checksums");
        for (i, cs) in checksums.iter().enumerate() {
            p.kv(&format!("[{i}]:"), cs);
        }
    }

    Ok(())
}

// -- list ----------------------------------------------------------------------

pub fn run_list(args: &VdexListArgs) -> Result<()> {
    let file = File::open(&args.file)
        .with_context(|| format!("cannot open '{}'", args.file.display()))?;
    let container = VdexFileContainer::new(&file);
    let vdex = container.open()?;

    let p = Printer::new(args.json, args.no_color);
    let n = vdex.num_dex_files();

    if n == 0 {
        if p.json {
            println!("[]");
        } else {
            eprintln!("No embedded DEX files.");
        }
        return Ok(());
    }

    if p.json {
        let entries: Vec<_> = (0..n)
            .map(|i| {
                let checksum = vdex.dex_checksum_at(i).unwrap_or(0);
                let size = vdex.get_dex_file_data(i).map(|d| d.len()).unwrap_or(0);
                json!({ "index": i, "checksum": format!("{checksum:#010x}"), "size": size })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&entries).unwrap());
        return Ok(());
    }

    p.section("Embedded DEX Files");
    for i in 0..n {
        let checksum = vdex.dex_checksum_at(i).unwrap_or(0);
        let size = match vdex.get_dex_file_data(i) {
            Ok(d) => format!("{} bytes", d.len()),
            Err(_) => "(unavailable)".to_string(),
        };
        p.kv(
            &format!("[{i}]:"),
            &format!("checksum={:#010x}  size={}", checksum, size),
        );
    }

    Ok(())
}

// -- extract -------------------------------------------------------------------

pub fn run_extract(args: &VdexExtractArgs) -> Result<()> {
    let file = File::open(&args.file)
        .with_context(|| format!("cannot open '{}'", args.file.display()))?;
    let container = VdexFileContainer::new(&file);
    let vdex = container.open()?;

    let n = vdex.num_dex_files();
    if !vdex.has_dex_section() {
        bail!("VDEX does not contain an embedded DEX file section");
    }
    if args.index >= n {
        bail!("DEX index {} is out of range (0..{})", args.index, n);
    }

    let dex_bytes = vdex.get_dex_file_data(args.index)?;
    std::fs::write(&args.output, dex_bytes).with_context(|| {
        format!("cannot write '{}'", args.output.display())
    })?;

    eprintln!(
        "Extracted DEX[{}] ({} bytes) -> {}",
        args.index,
        dex_bytes.len(),
        args.output.display()
    );
    Ok(())
}

// -- inspect -------------------------------------------------------------------

#[cfg(feature = "tui")]
pub fn run_inspect(args: &VdexInspectArgs) -> Result<()> {
    run_vdex_inspect(&args.file, args.index, args.output.clone())
}
