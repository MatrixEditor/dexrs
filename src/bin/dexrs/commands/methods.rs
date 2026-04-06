use anyhow::Result;
use serde_json::json;

use dexrs::file::dump::prettify;

use crate::{cli::MethodsArgs, commands::with_dex, output::{to_descriptor, Printer}};

pub fn run(args: &MethodsArgs) -> Result<()> {
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
                for m in acc.get_methods()? {
                    let name = dex.pretty_method_at(m.index, prettify::Method::WithSig);
                    let kind = if m.is_static_or_direct { "direct" } else { "virtual" };
                    let has_code = if m.code_offset > 0 { "yes" } else { "no" };
                    rows.push(vec![name, kind.to_string(), has_code.to_string()]);
                }
            }
        }

        if p.json {
            let entries: Vec<_> = rows
                .iter()
                .map(|r| json!({ "method": r[0], "kind": r[1], "has_code": r[2] == "yes" }))
                .collect();
            println!("{}", json!({ "methods": entries, "total": rows.len() }));
            return Ok(());
        }

        let total = rows.len();
        p.table(&["Method", "Kind", "Has Code"], rows);
        println!("\n  {total} method(s)");
        Ok(())
    })
}
