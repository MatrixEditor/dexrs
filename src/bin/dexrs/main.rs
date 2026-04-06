mod cli;
mod commands;
mod highlight;
mod output;
#[cfg(feature = "tui")]
mod tui;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Command};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Command::Info(args) => commands::info::run(args),
        Command::Map(args) => commands::map::run(args),
        Command::Classes(args) => commands::classes::run(args),
        Command::Class(args) => commands::class::run(args),
        Command::Methods(args) => commands::methods::run(args),
        Command::Fields(args) => commands::fields::run(args),
        Command::Disasm(args) => commands::disasm::run(args),
        Command::Strings(args) => commands::strings::run(args),
        Command::Types(args) => commands::types::run(args),
        Command::Patch(args) => match &args.command {
            cli::PatchCommand::Flags(a) => commands::patch::run_flags(a),
            cli::PatchCommand::Insn(a) => commands::patch::run_insn(a),
        },
        Command::Edit(args) => match &args.command {
            cli::EditCommand::RenameClass(a) => commands::edit::run_rename_class(a),
            cli::EditCommand::SetFlags(a) => commands::edit::run_set_flags(a),
            cli::EditCommand::SetMethodFlags(a) => commands::edit::run_set_method_flags(a),
            cli::EditCommand::ClearHiddenapi(a) => commands::edit::run_clear_hiddenapi(a),
            cli::EditCommand::BuildDex(a) => commands::edit::run_build_dex(a),
        },
        #[cfg(feature = "tui")]
        Command::Inspect(args) => commands::inspect::run(args),
        #[cfg(feature = "vdex")]
        Command::Vdex(args) => match &args.command {
            cli::VdexCommand::Info(a) => commands::vdex::run_info(a),
            cli::VdexCommand::List(a) => commands::vdex::run_list(a),
            cli::VdexCommand::Extract(a) => commands::vdex::run_extract(a),
            #[cfg(feature = "tui")]
            cli::VdexCommand::Inspect(a) => commands::vdex::run_inspect(a),
        },
    }
}
