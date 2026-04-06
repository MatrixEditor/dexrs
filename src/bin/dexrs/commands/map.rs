use anyhow::Result;
use serde_json::json;

use crate::{cli::MapArgs, commands::with_dex, output::Printer};

pub fn run(args: &MapArgs) -> Result<()> {
    let p = Printer::new(args.dex.json, args.dex.no_color);
    with_dex(&args.dex, |dex| {
        let items = match dex.get_map_list() {
            Some(m) => m,
            None => {
                p.error("map list is not available in this DEX file");
                return Ok(());
            }
        };

        if p.json {
            let entries: Vec<_> = items
                .iter()
                .map(|it| {
                    json!({
                        "type": format!("{:?}", it.type_),
                        "offset": it.off,
                        "count": it.size,
                    })
                })
                .collect();
            println!("{}", json!({ "sections": entries }));
            return Ok(());
        }

        let rows: Vec<Vec<String>> = items
            .iter()
            .map(|it| {
                vec![
                    format!("{:?}", it.type_),
                    format!("{:#010x}", it.off),
                    it.size.to_string(),
                ]
            })
            .collect();

        p.table(&["Section", "Offset", "Count"], rows);
        Ok(())
    })
}
