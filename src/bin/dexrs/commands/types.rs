use anyhow::Result;
use serde_json::json;

use crate::{cli::TypesArgs, commands::with_dex, output::{pretty_type, Printer}};

pub fn run(args: &TypesArgs) -> Result<()> {
    let p = Printer::new(args.dex.json, args.dex.no_color);

    with_dex(&args.dex, |dex| {
        let count = dex.num_type_ids();
        let mut rows: Vec<Vec<String>> = Vec::new();

        for idx in 0..count {
            let desc = dex.get_type_desc_utf16_lossy_at(idx as u16)?;
            rows.push(vec![idx.to_string(), desc.clone(), pretty_type(&desc)]);
        }

        if p.json {
            let entries: Vec<_> = rows
                .iter()
                .map(|r| json!({ "index": r[0], "descriptor": r[1], "pretty": r[2] }))
                .collect();
            println!("{}", json!({ "types": entries, "total": rows.len() }));
            return Ok(());
        }

        let total = rows.len();
        p.table(&["Index", "Descriptor", "Pretty"], rows);
        println!("\n  {total} type(s)");
        Ok(())
    })
}
