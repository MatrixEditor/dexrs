use dexrs::file::dump::prettify;
use dexrs::file::{vreg, DexFile, DexFileContainer, Field, InMemoryDexContainer, Method};
use dexrs::Result;
// use dexrs::art::dex::file::Header;

// fn main() -> Result<(), dexrs::art::error::Error> {

//     let file = std::fs::File::open(".vscode/classes.dex").unwrap();
//     let mmap = unsafe { memmap2::Mmap::map(&file)? };

//     let header = Header::from_bytes(&mmap).unwrap();
//     println!("Version: {}", header.get_version_or(0));
//     println!("{:?}", header);
//     Ok(())
// }

fn main() -> Result<()> {
    let path = ".vscode/classes.dex";
    let file = std::fs::File::open(&path).unwrap();
    let container = DexFileContainer::new(&file)
        .verify(true)
        .verify_checksum(true);

    let dex = container.open()?;
    println!("{:?}", dex.get_string_id(0)?);

    // println!("=== Types ===");
    // for type_id in dex.get_type_ids() {
    //     let name = dex.get_type_desc_utf16_lossy(type_id);
    //     println!("{}", name);
    // }

    // println!("=== Fields ===");
    // for field_id in dex.get_field_ids() {
    //     let cls_name = dex.get_type_desc_utf16_lossy_at(field_id.class_idx)?;
    //     let type_name = dex.get_type_desc_utf16_lossy_at(field_id.type_idx)?;
    //     let name = dex.get_utf16_str_lossy_at(field_id.name_idx)?;

    //     println!(".field {}->{}:{}", cls_name, name, type_name);
    // }

    let class_def = dex.get_class_def(122)?;
    let name = dex.get_type_desc_utf16_lossy_at(class_def.class_idx)?;
    println!("Class name: {}", name);

    if let Some(interfaces) = dex.get_type_list(class_def.interfaces_off)? {
        println!("Interfaces:");
        for interface in interfaces {
            let name = dex.get_type_desc_utf16_lossy_at(interface.type_idx)?;
            println!(".implements {}", name);
        }
    }

    let class_data = dex
        .get_class_accessor(class_def)
        .expect("msg")
        .expect("msg");
    println!("Static Methods: {}", class_data.num_direct_methods);
    let fields: Vec<Field> = class_data.get_fields().collect();

    for field in fields {
        println!(
            ".field {}",
            dex.pretty_field(field.index, prettify::Field::WithType)
        );
    }

    // for method in fields {
    //     let ca = dex.get_code_item_accessor(method.code_offset)?;
    //     let insn = ca.insn_at(0);
    //     println!("Insn: {:?}", insn.to_string(Some(&dex))?);
    // }

    let methods: Vec<Method> = class_data.get_methods()?.collect();
    for method in methods {
        println!(
            ".method {}",
            dex.pretty_method_at(method.index, prettify::Method::WithSig)
        );

        let ca = dex.get_code_item_accessor(method.code_offset)?;
        println!("    .registers {}\n", ca.registers_size());

        for inst in &ca {
            println!("|{:#08x}| {}", ca.get_inst_offset_in_code_units(&inst), inst.to_string(Some(&dex))?);
        }
        println!(".end method\n");
        break;
    }

    Ok(())
}
