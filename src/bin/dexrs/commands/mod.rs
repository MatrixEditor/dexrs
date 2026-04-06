pub mod class;
pub mod classes;
pub mod disasm;
pub mod edit;
pub mod fields;
pub mod info;
#[cfg(feature = "tui")]
pub mod inspect;
pub mod map;
pub mod methods;
pub mod patch;
pub mod strings;
pub mod types;
#[cfg(feature = "vdex")]
pub mod vdex;

use std::fs::File;

use dexrs::file::{DexFileContainer, MmapDexFile};

use crate::cli::DexArgs;

/// Open a DEX file from CLI args, respecting the `--no-verify` flag.
#[allow(dead_code)]
pub fn open_dex(args: &DexArgs) -> anyhow::Result<(File, DexFileContainer)> {
    let file = File::open(&args.file)
        .map_err(|e| anyhow::anyhow!("cannot open '{}': {e}", args.file.display()))?;
    let container = DexFileContainer::new(&file).verify(!args.no_verify);
    Ok((file, container))
}

/// Helper that opens a dex file and calls a closure with the parsed file.
pub fn with_dex<F, R>(args: &DexArgs, f: F) -> anyhow::Result<R>
where
    F: for<'a> FnOnce(&MmapDexFile<'a>) -> anyhow::Result<R>,
{
    let file = File::open(&args.file)
        .map_err(|e| anyhow::anyhow!("cannot open '{}': {e}", args.file.display()))?;
    let container = DexFileContainer::new(&file).verify(!args.no_verify);
    let dex = container.open()?;
    f(&dex)
}
