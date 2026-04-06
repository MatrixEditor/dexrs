use anyhow::Result;
use serde_json::json;

use crate::{
    cli::InfoArgs,
    commands::with_dex,
    output::{format_flags, Printer},
};

pub fn run(args: &InfoArgs) -> Result<()> {
    let p = Printer::new(args.dex.json, args.dex.no_color);
    with_dex(&args.dex, |dex| {
        let h = dex.get_header();
        let magic = h.get_magic();
        let sig = h.get_signature();
        let sig_hex: String = sig.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("");

        let format = if dex.is_compact_dex() { "Compact DEX (cdex)" } else { "Standard DEX" };
        let version = h.get_version();
        let location = dex.get_location();

        if p.json {
            println!(
                "{}",
                json!({
                    "format": format,
                    "version": version,
                    "location": location.to_string(),
                    "magic": format!("{}", String::from_utf8_lossy(magic)),
                    "checksum": h.checksum,
                    "signature": sig_hex,
                    "file_size": h.file_size,
                    "header_size": h.header_size,
                    "endian_tag": format!("{:#010x}", h.endian_tag),
                    "map_off": h.map_off,
                    "strings": h.string_ids_size,
                    "types": h.type_ids_size,
                    "protos": h.proto_ids_size,
                    "fields": h.field_ids_size,
                    "methods": h.method_ids_size,
                    "classes": h.class_defs_size,
                    "data_size": h.data_size,
                    "data_off": h.data_off,
                })
            );
            return Ok(());
        }

        p.section("File");
        p.kv("Format:", format);
        p.kv("Version:", &version.to_string());
        p.kv("Location:", &location.to_string());
        p.kv("File size:", &format!("{} bytes", h.file_size));

        p.section("Integrity");
        p.kv("Checksum:", &format!("{:#010x}", h.checksum));
        p.kv("SHA-1:", &sig_hex);

        p.section("Header");
        p.kv("Header size:", &format!("{} bytes", h.header_size));
        p.kv("Endian tag:", &format!("{:#010x}", h.endian_tag));
        p.kv("Map offset:", &format!("{:#010x}", h.map_off));
        p.kv("Data:", &format!("{} bytes @ {:#x}", h.data_size, h.data_off));
        p.kv("Link:", &format!("{} bytes @ {:#x}", h.link_size, h.link_off));

        p.section("Counts");
        p.kv("Strings:", &h.string_ids_size.to_string());
        p.kv("Types:", &h.type_ids_size.to_string());
        p.kv("Protos:", &h.proto_ids_size.to_string());
        p.kv("Fields:", &h.field_ids_size.to_string());
        p.kv("Methods:", &h.method_ids_size.to_string());
        p.kv("Classes:", &h.class_defs_size.to_string());

        p.section("Method handles / call sites");
        p.kv("Method handles:", &dex.num_method_handles().to_string());
        p.kv("Call site IDs:", &dex.num_call_site_ids().to_string());

        // Access flags of the first class (just as a sample check)
        if h.class_defs_size > 0 {
            if let Ok(cd) = dex.get_class_def(0) {
                let _flags = format_flags(cd.access_flags);
            }
        }

        Ok(())
    })
}
