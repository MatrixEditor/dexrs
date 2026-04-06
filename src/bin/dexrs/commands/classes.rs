use anyhow::Result;
use serde_json::json;

use crate::{cli::ClassesArgs, commands::with_dex, output::Printer};

pub fn run(args: &ClassesArgs) -> Result<()> {
    let p = Printer::new(args.dex.json, args.dex.no_color);
    let filter = args.filter.as_deref().map(str::to_lowercase);

    with_dex(&args.dex, |dex| {
        let count = dex.num_class_defs();
        let mut rows: Vec<Vec<String>> = Vec::new();

        for idx in 0..count {
            let cd = dex.get_class_def(idx)?;
            let desc = dex.get_class_desc_utf16_lossy(cd)?;
            let pretty = dexrs::desc_names::pretty_desc(&desc);

            if let Some(ref f) = filter {
                if !pretty.to_lowercase().contains(f.as_str())
                    && !desc.to_lowercase().contains(f.as_str())
                {
                    continue;
                }
            }

            let flags = cd.access_flags;
            let superclass = if cd.superclass_idx != u16::MAX {
                dex.get_type_desc_utf16_lossy_at(cd.superclass_idx)
                    .map(|s| dexrs::desc_names::pretty_desc(&s))
                    .unwrap_or_default()
            } else {
                String::new()
            };

            rows.push(vec![
                pretty,
                crate::output::format_flags(flags),
                superclass,
            ]);
        }

        if p.json {
            let entries: Vec<_> = rows
                .iter()
                .map(|r| json!({ "class": r[0], "flags": r[1], "superclass": r[2] }))
                .collect();
            println!("{}", json!({ "classes": entries, "total": rows.len() }));
            return Ok(());
        }

        let total = rows.len();
        p.table(&["Class", "Access Flags", "Superclass"], rows);
        println!("\n  {total} class(es)");
        Ok(())
    })
}
