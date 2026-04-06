use anyhow::Result;
use serde_json::json;

use dexrs::file::{dump::prettify, ClassAccessor};

use crate::{
    cli::ClassArgs,
    commands::with_dex,
    output::{format_flags, pretty_type, to_descriptor, Printer},
};

pub fn run(args: &ClassArgs) -> Result<()> {
    let p = Printer::new(args.dex.json, args.dex.no_color);
    let target_desc = to_descriptor(&args.class);

    with_dex(&args.dex, |dex| {
        // Find class by descriptor
        let class_def = {
            let mut found = None;
            for idx in 0..dex.num_class_defs() {
                let cd = dex.get_class_def(idx)?;
                let desc = dex.get_class_desc_utf16_lossy(cd)?;
                if desc == target_desc
                    || dexrs::desc_names::pretty_desc(&desc) == args.class
                {
                    found = Some(cd);
                    break;
                }
            }
            match found {
                Some(c) => c,
                None => {
                    p.error(&format!("class '{}' not found", args.class));
                    return Ok(());
                }
            }
        };

        let desc = dex.get_class_desc_utf16_lossy(class_def)?;
        let class_name = pretty_type(&desc);
        let flags = format_flags(class_def.access_flags);

        let superclass = if class_def.superclass_idx != u16::MAX {
            dex.get_type_desc_utf16_lossy_at(class_def.superclass_idx)
                .map(|s| pretty_type(&s))
                .unwrap_or_default()
        } else {
            String::new()
        };

        let interfaces: Vec<String> = if let Ok(Some(list)) =
            dex.get_interfaces_list(class_def)
        {
            list.iter()
                .map(|t| {
                    dex.get_type_desc_utf16_lossy_at(t.type_idx)
                        .map(|s| pretty_type(&s))
                        .unwrap_or_else(|_| format!("type@{}", t.type_idx))
                })
                .collect()
        } else {
            vec![]
        };

        let accessor: Option<ClassAccessor<'_>> = dex.get_class_accessor(class_def)?;

        let mut methods: Vec<(String, String, u32)> = vec![];
        let mut fields: Vec<(String, String, String)> = vec![];

        if let Some(acc) = &accessor {
            for m in acc.get_methods()? {
                let name = dex.pretty_method_at(m.index, prettify::Method::WithSig);
                let kind = if m.is_static_or_direct { "direct" } else { "virtual" };
                methods.push((name, kind.to_string(), m.code_offset));
            }
            for f in acc.get_fields() {
                let name = dex.pretty_field_at(f.index, prettify::Field::WithType);
                let kind = if f.is_static { "static" } else { "instance" };
                fields.push((name, kind.to_string(), format_flags(f.access_flags)));
            }
        }

        if p.json {
            println!(
                "{}",
                json!({
                    "class": class_name,
                    "descriptor": desc,
                    "flags": flags,
                    "superclass": superclass,
                    "interfaces": interfaces,
                    "methods": methods.iter().map(|(n, k, off)| json!({
                        "name": n,
                        "kind": k,
                        "code_offset": off,
                    })).collect::<Vec<_>>(),
                    "fields": fields.iter().map(|(n, k, f)| json!({
                        "name": n,
                        "kind": k,
                        "flags": f,
                    })).collect::<Vec<_>>(),
                })
            );
            return Ok(());
        }

        p.section("Class");
        p.kv("Name:", &class_name);
        p.kv("Descriptor:", &desc);
        p.kv("Access flags:", &flags);
        if !superclass.is_empty() {
            p.kv("Superclass:", &superclass);
        }
        if !interfaces.is_empty() {
            p.kv("Interfaces:", &interfaces.join(", "));
        }

        p.section(&format!("Methods ({})", methods.len()));
        for (name, kind, _) in &methods {
            p.item(&format!("[{kind}] {name}"));
        }

        p.section(&format!("Fields ({})", fields.len()));
        for (name, kind, flags) in &fields {
            let flag_str = if flags.is_empty() {
                String::new()
            } else {
                format!("  [{flags}]")
            };
            p.item(&format!("[{kind}] {name}{flag_str}"));
        }

        Ok(())
    })
}
