use anyhow::{Context, Result};
use std::io::{self, BufRead};

use crate::cli::{
    EditBuildDexArgs, EditClearHiddenapiArgs, EditRenameClassArgs, EditSetFlagsArgs,
    EditSetMethodFlagsArgs,
};

fn parse_int(s: &str) -> Result<u32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Ok(u32::from_str_radix(hex, 16).context("invalid hex value")?)
    } else {
        Ok(s.parse::<u32>().context("invalid decimal value")?)
    }
}

pub fn run_rename_class(args: &EditRenameClassArgs) -> Result<()> {
    let mut editor = dexrs::file::DexEditor::from_file(&args.file)
        .with_context(|| format!("cannot open '{}'", args.file.display()))?;
    editor
        .rename_class(&args.old_name, &args.new_name)
        .context("rename_class")?;
    editor
        .write_to(&args.output)
        .with_context(|| format!("cannot write '{}'", args.output.display()))?;
    eprintln!("written: {}", args.output.display());
    Ok(())
}

pub fn run_set_flags(args: &EditSetFlagsArgs) -> Result<()> {
    let flags = parse_int(&args.flags).context("--flags")?;
    let mut editor = dexrs::file::DexEditor::from_file(&args.file)
        .with_context(|| format!("cannot open '{}'", args.file.display()))?;
    editor
        .set_class_access_flags(&args.class, flags)
        .context("set_class_access_flags")?;
    editor
        .write_to(&args.output)
        .with_context(|| format!("cannot write '{}'", args.output.display()))?;
    eprintln!("written: {}", args.output.display());
    Ok(())
}

pub fn run_set_method_flags(args: &EditSetMethodFlagsArgs) -> Result<()> {
    let flags = parse_int(&args.flags).context("--flags")?;
    let mut editor = dexrs::file::DexEditor::from_file(&args.file)
        .with_context(|| format!("cannot open '{}'", args.file.display()))?;
    editor
        .set_method_access_flags(&args.class, &args.method, flags)
        .context("set_method_access_flags")?;
    editor
        .write_to(&args.output)
        .with_context(|| format!("cannot write '{}'", args.output.display()))?;
    eprintln!("written: {}", args.output.display());
    Ok(())
}

pub fn run_clear_hiddenapi(args: &EditClearHiddenapiArgs) -> Result<()> {
    let mut editor = dexrs::file::DexEditor::from_file(&args.file)
        .with_context(|| format!("cannot open '{}'", args.file.display()))?;
    editor.clear_hiddenapi_flags().context("clear_hiddenapi_flags")?;
    editor
        .write_to(&args.output)
        .with_context(|| format!("cannot write '{}'", args.output.display()))?;
    eprintln!("written: {}", args.output.display());
    Ok(())
}

// --- build-dex ----------------------------------------------------------------

/// Assemble a new DEX file from a plain-text class/method description.
///
/// **Input format** (lines starting with `#` are comments):
///
/// ```text
/// .class Lcom/example/Hello; public
/// .super Ljava/lang/Object;
/// .source Hello.java
///
/// .method main ([Ljava/lang/String;)V public static
/// .registers 3 1 2
/// sget-object v0, Ljava/lang/System;->out:Ljava/io/PrintStream;
/// const-string v1, "Hello!"
/// invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V
/// return-void
/// .end method
///
/// .end class
/// ```
pub fn run_build_dex(args: &EditBuildDexArgs) -> Result<()> {
    let lines: Vec<String> = if args.input == "-" {
        io::stdin().lock().lines().collect::<io::Result<_>>().context("reading stdin")?
    } else {
        let f = std::fs::File::open(&args.input)
            .with_context(|| format!("cannot open '{}'", args.input))?;
        io::BufReader::new(f).lines().collect::<io::Result<_>>().context("reading input")?
    };

    let ir = parse_build_input(&lines, args.dex_version).context("parsing build input")?;
    let bytes = dexrs::file::DexWriter::write(ir).context("assembling DEX")?;
    std::fs::write(&args.output, &bytes)
        .with_context(|| format!("cannot write '{}'", args.output.display()))?;
    eprintln!("written: {} ({} bytes)", args.output.display(), bytes.len());
    Ok(())
}

fn parse_build_input(lines: &[String], version: u32) -> Result<dexrs::file::DexIr> {
    use dexrs::file::{builder::CodeBuilder, ir::{ClassDef, MethodDef, ProtoKey}, DexIr};

    let mut ir = DexIr::new(version);
    let mut class_stack: Vec<ClassDef> = Vec::new();

    struct MethodCtx {
        name: String,
        proto: ProtoKey,
        access: u32,
        code: Option<CodeBuilder>,
        is_direct: bool,
    }
    let mut method_ctx: Option<MethodCtx> = None;

    for (lineno, raw) in lines.iter().enumerate() {
        let line = raw.trim();
        let line = if let Some(pos) = line.find('#') { &line[..pos] } else { line }.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(rest) = line.strip_prefix(".class ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            let desc = parts.first().copied().context(".class needs descriptor")?;
            let access = parse_access_flags(&parts[1..]);
            class_stack.push(ClassDef::new(desc).access(access));

        } else if let Some(rest) = line.strip_prefix(".super ") {
            class_stack.last_mut().context(".super outside .class")?.superclass =
                Some(rest.trim().to_string());

        } else if let Some(rest) = line.strip_prefix(".source ") {
            class_stack.last_mut().context(".source outside .class")?.source_file =
                Some(rest.trim().to_string());

        } else if let Some(rest) = line.strip_prefix(".implements ") {
            class_stack.last_mut().context(".implements outside .class")?.interfaces
                .push(rest.trim().to_string());

        } else if line == ".end class" {
            ir.add_class(class_stack.pop().context(".end class without .class")?);

        } else if let Some(rest) = line.strip_prefix(".method ") {
            anyhow::ensure!(method_ctx.is_none(), "line {}: nested .method", lineno + 1);
            let parts: Vec<&str> = rest.split_whitespace().collect();
            anyhow::ensure!(parts.len() >= 2, "line {}: .method needs name and descriptor", lineno + 1);
            let name = parts[0];
            let proto = ProtoKey::from_descriptor(parts[1])
                .ok_or_else(|| anyhow::anyhow!("line {}: invalid descriptor {:?}", lineno + 1, parts[1]))?;
            let access = parse_access_flags(&parts[2..]);
            let is_direct = name.starts_with('<')
                || access & 0x0008 != 0
                || access & 0x0002 != 0;
            method_ctx = Some(MethodCtx { name: name.to_string(), proto, access, code: None, is_direct });

        } else if let Some(rest) = line.strip_prefix(".registers ") {
            let ctx = method_ctx.as_mut().context(".registers outside .method")?;
            let nums: Vec<u16> = rest
                .split_whitespace()
                .map(|s| s.parse::<u16>().context("invalid number"))
                .collect::<Result<_>>()?;
            anyhow::ensure!(nums.len() == 3, "line {}: .registers needs exactly 3 values", lineno + 1);
            ctx.code = Some(CodeBuilder::new(nums[0], nums[1], nums[2]));

        } else if line == ".end method" {
            let ctx = method_ctx.take().context(".end method without .method")?;
            let code = ctx.code.map(|cb| cb.build()).transpose()
                .with_context(|| format!("assembling method {:?}", ctx.name))?;
            let mut method = MethodDef::new(ctx.name, ctx.proto).access(ctx.access);
            if let Some(c) = code { method.code = Some(c); }
            let cls = class_stack.last_mut().context(".end method outside .class")?;
            if ctx.is_direct { cls.direct_methods.push(method); } else { cls.virtual_methods.push(method); }

        } else if let Some(ctx) = method_ctx.as_mut() {
            let cb = ctx.code.get_or_insert_with(|| CodeBuilder::new(0, 0, 0));
            if let Some(lbl) = line.strip_prefix(':') {
                cb.label(lbl);
            } else {
                cb.emit(line).with_context(|| format!("line {}: {:?}", lineno + 1, line))?;
            }

        } else {
            anyhow::bail!("line {}: unexpected directive {:?}", lineno + 1, line);
        }
    }

    anyhow::ensure!(class_stack.is_empty(), "unclosed .class block");
    Ok(ir)
}

fn parse_access_flags(tokens: &[&str]) -> u32 {
    tokens.iter().fold(0u32, |acc, t| {
        acc | match *t {
            "public" => 0x0001,
            "private" => 0x0002,
            "protected" => 0x0004,
            "static" => 0x0008,
            "final" => 0x0010,
            "synchronized" => 0x0020,
            "abstract" => 0x0400,
            "interface" => 0x0200,
            "native" => 0x0100,
            "constructor" => 0x10000,
            _ => {
                if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    u32::from_str_radix(hex, 16).unwrap_or(0)
                } else {
                    t.parse().unwrap_or(0)
                }
            }
        }
    })
}

