use anyhow::Result;
use serde_json::json;

use dexrs::file::dump::prettify;

use crossterm::style::Stylize;

use crate::{
    cli::DisasmArgs,
    commands::with_dex,
    highlight,
    output::{format_flags, to_descriptor, Printer},
};

/// Parse "com.example.Foo#bar" or "com.example.Foo#bar(int, String)" into
/// (descriptor, method_name_prefix).
fn parse_method_spec(spec: &str) -> (String, String) {
    if let Some(pos) = spec.rfind('#') {
        let class_part = &spec[..pos];
        let method_part = &spec[pos + 1..];
        (to_descriptor(class_part), method_part.to_string())
    } else {
        // No '#', treat entire thing as a method name substring
        (String::new(), spec.to_string())
    }
}

pub fn run(args: &DisasmArgs) -> Result<()> {
    let p = Printer::new(args.dex.json, args.dex.no_color);
    let (class_desc, method_name_prefix) = parse_method_spec(&args.method);

    with_dex(&args.dex, |dex| {
        for idx in 0..dex.num_class_defs() {
            let cd = dex.get_class_def(idx)?;

            if !class_desc.is_empty() {
                let desc = dex.get_class_desc_utf16_lossy(cd)?;
                if desc != class_desc {
                    continue;
                }
            }

            let accessor = dex.get_class_accessor(cd)?;
            let acc = match accessor {
                Some(a) => a,
                None => continue,
            };

            for m in acc.get_methods()? {
                let method_id = dex.get_method_id(m.index)?;
                let name = dex.get_str_lossy_at(method_id.name_idx)?;
                if !name.contains(&method_name_prefix) {
                    continue;
                }

                let full_name = dex.pretty_method_at(m.index, prettify::Method::WithSig);
                let flags = format_flags(m.access_flags);
                let code_off = m.code_offset;

                disasm_method(
                    dex,
                    &full_name,
                    &flags,
                    code_off,
                    &p,
                )?;
            }
        }
        Ok(())
    })
}

fn disasm_method<'a, C>(
    dex: &dexrs::file::DexFile<'a, C>,
    full_name: &str,
    flags: &str,
    code_off: u32,
    p: &Printer,
) -> Result<()>
where
    C: dexrs::file::DexContainer<'a>,
{
    if p.json {
        let insns = collect_disasm(dex, code_off)?;
        println!(
            "{}",
            json!({
                "method": full_name,
                "flags": flags,
                "code_offset": code_off,
                "instructions": insns,
            })
        );
        return Ok(());
    }

    p.section(&format!(".method {flags} {full_name}"));

    if code_off == 0 {
        p.item("(abstract / native — no code)");
        return Ok(());
    }

    let ca = dex.get_code_item_accessor(code_off)?;
    p.item(&format!(
        "  registers: {}   ins: {}   outs: {}   tries: {}",
        ca.registers_size(),
        ca.ins_size(),
        ca.outs_size(),
        ca.tries_size(),
    ));
    println!();

    let mut pc: u32 = 0;
    for insn in ca {
        let styled = insn.to_styled(Some(dex)).unwrap_or_else(|_| vec![dexrs::file::dump::Span {
            text: "<decode error>".to_string(),
            hl: dexrs::file::dump::Highlight::Plain,
        }]);
        let colored = highlight::to_cli_string(&styled, p.color);
        if p.color {
            println!("    {}  {colored}", format!("{pc:04x}").dim());
        } else {
            println!("    {pc:04x}  {colored}");
        }
        pc += insn.size_in_code_units() as u32;
    }

    println!(".end method\n");
    Ok(())
}

fn collect_disasm<'a, C>(
    dex: &dexrs::file::DexFile<'a, C>,
    code_off: u32,
) -> Result<Vec<serde_json::Value>>
where
    C: dexrs::file::DexContainer<'a>,
{
    if code_off == 0 {
        return Ok(vec![]);
    }
    let ca = dex.get_code_item_accessor(code_off)?;
    let mut insns = Vec::new();
    let mut pc: u32 = 0;
    for insn in ca {
        let text = insn.to_string(Some(dex)).unwrap_or_else(|_| "<decode error>".to_string());
        insns.push(json!({ "pc": pc, "text": text }));
        pc += insn.size_in_code_units() as u32;
    }
    Ok(insns)
}
