use anyhow::Result;
use serde_json::json;

use dexrs::file::dump::prettify;

use crate::{cli::FieldsArgs, commands::with_dex, output::{format_flags, to_descriptor, Printer}};

pub fn run(args: &FieldsArgs) -> Result<()> {
    let p = Printer::new(args.dex.json, args.dex.no_color);
    let class_filter = args.class.as_deref().map(to_descriptor);

    with_dex(&args.dex, |dex| {
        let mut rows: Vec<Vec<String>> = Vec::new();

        for idx in 0..dex.num_class_defs() {
            let cd = dex.get_class_def(idx)?;

            if let Some(ref filter_desc) = class_filter {
                let desc = dex.get_class_desc_utf16_lossy(cd)?;
                if &desc != filter_desc {
                    continue;
                }
            }

            let accessor = dex.get_class_accessor(cd)?;
            if let Some(acc) = accessor {
                for f in acc.get_fields() {
                    let name = dex.pretty_field_at(f.index, prettify::Field::WithType);
                    let kind = if f.is_static { "static" } else { "instance" };
                    rows.push(vec![name, kind.to_string(), format_flags(f.access_flags)]);
                }
            }
        }

        if p.json {
            let entries: Vec<_> = rows
                .iter()
                .map(|r| json!({ "field": r[0], "kind": r[1], "flags": r[2] }))
                .collect();
            println!("{}", json!({ "fields": entries, "total": rows.len() }));
            return Ok(());
        }

        let total = rows.len();
        p.table(&["Field", "Kind", "Access Flags"], rows);
        println!("\n  {total} field(s)");
        Ok(())
    })
}
