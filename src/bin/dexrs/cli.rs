use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "dexrs",
    about = "Inspect and analyse Android DEX files",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Flags shared by every subcommand that reads a DEX file.
#[derive(Args, Clone)]
pub struct DexArgs {
    /// Path to the DEX file
    pub file: std::path::PathBuf,

    /// Emit JSON instead of human-readable output
    #[arg(long, global = false)]
    pub json: bool,

    /// Disable ANSI colour in output
    #[arg(long, global = false)]
    pub no_color: bool,

    /// Skip DEX file verification
    #[arg(long, global = false)]
    pub no_verify: bool,
}

#[derive(Subcommand)]
pub enum Command {
    /// Show file header: magic, version, checksums, section counts
    Info(InfoArgs),
    /// Show the DEX section map (type, offset, size, count)
    Map(MapArgs),
    /// List all classes (optionally filtered)
    Classes(ClassesArgs),
    /// Show full details of a single class
    Class(ClassArgs),
    /// List all methods (optionally filtered by class)
    Methods(MethodsArgs),
    /// List all fields (optionally filtered by class)
    Fields(FieldsArgs),
    /// Disassemble a method to Dalvik bytecode
    Disasm(DisasmArgs),
    /// Dump all strings from the string pool
    Strings(StringsArgs),
    /// List all type descriptors
    Types(TypesArgs),
    /// Patch access flags on a class definition in-place (updates checksum)
    Patch(PatchArgs),
    /// Structural DEX edits written to an output file
    Edit(EditArgs),
    /// Launch the interactive TUI inspector
    #[cfg(feature = "tui")]
    Inspect(InspectArgs),
    /// Inspect and extract VDEX files (EXPERIMENTAL)
    #[cfg(feature = "vdex")]
    Vdex(VdexArgs),
}

#[derive(Args)]
pub struct InfoArgs {
    #[command(flatten)]
    pub dex: DexArgs,
}

#[derive(Args)]
pub struct MapArgs {
    #[command(flatten)]
    pub dex: DexArgs,
}

#[derive(Args)]
pub struct ClassesArgs {
    #[command(flatten)]
    pub dex: DexArgs,
    /// Filter classes by substring or glob pattern (e.g. "com.example.*")
    #[arg(long, short = 'f')]
    pub filter: Option<String>,
}

#[derive(Args)]
pub struct ClassArgs {
    #[command(flatten)]
    pub dex: DexArgs,
    /// Fully-qualified class name or descriptor (e.g. "com.example.Main" or "Lcom/example/Main;")
    pub class: String,
}

#[derive(Args)]
pub struct MethodsArgs {
    #[command(flatten)]
    pub dex: DexArgs,
    /// Only show methods belonging to this class
    #[arg(long, short = 'c')]
    pub class: Option<String>,
}

#[derive(Args)]
pub struct FieldsArgs {
    #[command(flatten)]
    pub dex: DexArgs,
    /// Only show fields belonging to this class
    #[arg(long, short = 'c')]
    pub class: Option<String>,
}

#[derive(Args)]
pub struct DisasmArgs {
    #[command(flatten)]
    pub dex: DexArgs,
    /// Method to disassemble: "com.example.Foo#methodName" or descriptor form
    pub method: String,
}

#[derive(Args)]
pub struct StringsArgs {
    #[command(flatten)]
    pub dex: DexArgs,
    /// Only show strings containing this substring
    #[arg(long, short = 'f')]
    pub filter: Option<String>,
}

#[derive(Args)]
pub struct TypesArgs {
    #[command(flatten)]
    pub dex: DexArgs,
}

#[cfg(feature = "tui")]
#[derive(Args)]
pub struct InspectArgs {
    /// Path to the DEX file
    pub file: std::path::PathBuf,
    /// Skip DEX file verification
    #[arg(long)]
    pub no_verify: bool,
    /// Write edited DEX to this path (enables in-TUI editing with [e] and [f])
    #[arg(long, short = 'o')]
    pub output: Option<std::path::PathBuf>,
}

// --- patch -------------------------------------------------------------------

#[derive(Args)]
pub struct PatchArgs {
    #[command(subcommand)]
    pub command: PatchCommand,
}

#[derive(Subcommand)]
pub enum PatchCommand {
    /// Patch access flags on a class definition
    Flags(PatchFlagsArgs),
    /// Overwrite a single instruction word (u16) in a code item
    Insn(PatchInsnArgs),
}

#[derive(Args)]
pub struct PatchFlagsArgs {
    /// Path to the DEX file (modified in-place)
    pub file: std::path::PathBuf,
    /// Fully-qualified class name or descriptor
    #[arg(long, short = 'c')]
    pub class: String,
    /// New access flags value (decimal or 0x-prefixed hex)
    #[arg(long)]
    pub flags: String,
}

#[derive(Args)]
pub struct PatchInsnArgs {
    /// Path to the DEX file (modified in-place)
    pub file: std::path::PathBuf,
    /// Byte offset of the code item in the file (decimal or 0x-prefixed hex)
    #[arg(long)]
    pub code_offset: String,
    /// Code-unit PC within the code item (decimal)
    #[arg(long)]
    pub pc: u32,
    /// Replacement instruction word (decimal or 0x-prefixed hex)
    #[arg(long)]
    pub word: String,
}

// --- edit --------------------------------------------------------------------

#[derive(Args)]
pub struct EditArgs {
    #[command(subcommand)]
    pub command: EditCommand,
}

#[derive(Subcommand)]
pub enum EditCommand {
    /// Rename a class (updates string pool and all cross-references)
    RenameClass(EditRenameClassArgs),
    /// Set access flags on a class
    SetFlags(EditSetFlagsArgs),
    /// Set access flags on a method
    SetMethodFlags(EditSetMethodFlagsArgs),
    /// Remove hidden API restriction flags
    ClearHiddenapi(EditClearHiddenapiArgs),
    /// Build a new DEX by assembling classes from a smali-like text description
    BuildDex(EditBuildDexArgs),
}

#[derive(Args)]
pub struct EditRenameClassArgs {
    pub file: std::path::PathBuf,
    pub old_name: String,
    pub new_name: String,
    #[arg(long, short = 'o')]
    pub output: std::path::PathBuf,
}

#[derive(Args)]
pub struct EditSetFlagsArgs {
    pub file: std::path::PathBuf,
    #[arg(long, short = 'c')]
    pub class: String,
    /// New access flags (decimal or 0x-prefixed hex)
    #[arg(long)]
    pub flags: String,
    #[arg(long, short = 'o')]
    pub output: std::path::PathBuf,
}

#[derive(Args)]
pub struct EditSetMethodFlagsArgs {
    pub file: std::path::PathBuf,
    /// Class descriptor or dotted name
    #[arg(long, short = 'c')]
    pub class: String,
    /// Method name (without signature)
    #[arg(long, short = 'm')]
    pub method: String,
    /// New access flags (decimal or 0x-prefixed hex)
    #[arg(long)]
    pub flags: String,
    #[arg(long, short = 'o')]
    pub output: std::path::PathBuf,
}

#[derive(Args)]
pub struct EditClearHiddenapiArgs {
    pub file: std::path::PathBuf,
    #[arg(long, short = 'o')]
    pub output: std::path::PathBuf,
}

// --- edit build-dex -----------------------------------------------------------

/// Build a new DEX file from a plain-text class/method description.
///
/// The input file format (one directive per line):
///
/// ```text
/// .class Lcom/example/Hello; public
/// .super Ljava/lang/Object;
/// .method main ([Ljava/lang/String;)V public static
/// .registers 3 1 2
/// sget-object v0, Ljava/lang/System;->out:Ljava/io/PrintStream;
/// const-string v1, "Hello!"
/// invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V
/// return-void
/// .end method
/// .end class
/// ```
#[derive(Args)]
pub struct EditBuildDexArgs {
    /// Path to the plain-text class description (use `-` for stdin)
    pub input: String,
    /// Output DEX file path
    #[arg(long, short = 'o')]
    pub output: std::path::PathBuf,
    /// DEX version to target (default: 35)
    #[arg(long, default_value = "35")]
    pub dex_version: u32,
}

// --- vdex ---------------------------------------------------------------------

#[cfg(feature = "vdex")]
#[derive(Args)]
pub struct VdexArgs {
    #[command(subcommand)]
    pub command: VdexCommand,
}

#[cfg(feature = "vdex")]
#[derive(Subcommand)]
pub enum VdexCommand {
    /// Show the VDEX file header, sections, and embedded DEX checksums
    Info(VdexInfoArgs),
    /// List all embedded DEX files with index, checksum, and size
    List(VdexListArgs),
    /// Extract an embedded DEX file to disk
    Extract(VdexExtractArgs),
    /// Launch the interactive TUI inspector on an embedded DEX
    #[cfg(feature = "tui")]
    Inspect(VdexInspectArgs),
}

#[cfg(feature = "vdex")]
#[derive(Args)]
pub struct VdexInfoArgs {
    /// Path to the VDEX file
    pub file: std::path::PathBuf,
    /// Emit JSON instead of human-readable output
    #[arg(long)]
    pub json: bool,
    /// Disable ANSI colour in output
    #[arg(long)]
    pub no_color: bool,
}

#[cfg(feature = "vdex")]
#[derive(Args)]
pub struct VdexListArgs {
    /// Path to the VDEX file
    pub file: std::path::PathBuf,
    /// Emit JSON instead of human-readable output
    #[arg(long)]
    pub json: bool,
    /// Disable ANSI colour in output
    #[arg(long)]
    pub no_color: bool,
}

#[cfg(feature = "vdex")]
#[derive(Args)]
pub struct VdexExtractArgs {
    /// Path to the VDEX file
    pub file: std::path::PathBuf,
    /// Zero-based index of the DEX file to extract
    #[arg(long, short = 'i', default_value = "0")]
    pub index: u32,
    /// Output path for the extracted DEX file
    #[arg(long, short = 'o')]
    pub output: std::path::PathBuf,
}

#[cfg(all(feature = "vdex", feature = "tui"))]
#[derive(Args)]
pub struct VdexInspectArgs {
    /// Path to the VDEX file
    pub file: std::path::PathBuf,
    /// Zero-based index of the embedded DEX to inspect (default: 0, or pick interactively)
    #[arg(long, short = 'i')]
    pub index: Option<u32>,
    /// Write edited DEX to this path (enables in-TUI editing)
    #[arg(long, short = 'o')]
    pub output: Option<std::path::PathBuf>,
}
