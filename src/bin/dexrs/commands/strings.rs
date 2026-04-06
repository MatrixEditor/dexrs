use anyhow::Result;
use serde_json::json;

use crate::{cli::StringsArgs, commands::with_dex, output::Printer};

pub fn run(args: &StringsArgs) -> Result<()> {
    let p = Printer::new(args.dex.json, args.dex.no_color);
    let filter = args.filter.as_deref().map(str::to_lowercase);

    with_dex(&args.dex, |dex| {
        let count = dex.num_string_ids();
        let mut results: Vec<(u32, String)> = Vec::new();

        for idx in 0..count {
            let s = dex.get_str_lossy_at(idx)?;
            if let Some(ref f) = filter {
                if !s.to_lowercase().contains(f.as_str()) {
                    continue;
                }
            }
            results.push((idx, s));
        }

        if p.json {
            let entries: Vec<_> = results
                .iter()
                .map(|(i, s)| json!({ "index": i, "value": s }))
                .collect();
            println!("{}", json!({ "strings": entries, "total": results.len() }));
            return Ok(());
        }

        let rows: Vec<Vec<String>> = results
            .iter()
            .map(|(i, s)| vec![i.to_string(), s.clone()])
            .collect();

        let total = rows.len();
        p.table(&["Index", "String"], rows);
        println!("\n  {total} string(s)");
        Ok(())
    })
}
