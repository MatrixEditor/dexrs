#![allow(unused)]

use dexrs::file::dump::prettify;
use dexrs::file::DexFile;
use dexrs::Result;
use openssl::string;

fn dex_get_method(dex: &DexFile<'_>) -> Result<()> {
    // the DexFile struct does not provide an interface to query all
    // method related information all at once, so we have to fetch
    // all method information one by one.
    let method_id = dex.get_method_id(0)?;

    // index can be retrieved from the MethodIdItem
    assert!(dex.method_id_idx(method_id)? == 0);

    // name is a string. To resolve everything manually, you would need
    // to fetch the string id first
    let name = dex.get_utf16_str_at(method_id.name_idx)?;
    let proto_id = dex.get_proto_id(method_id.proto_idx)?;

    // the declaring class name is just a TypeId, which points to a
    // string id
    let class_name = dex.get_type_desc_utf16_at(method_id.class_idx)?;

    // you can either print the method by yourself or get a prettified
    // version. You can specify whether to print the signature or not
    let pretty_method = dex.pretty_method_opt(method_id, prettify::Method::WithSig)?;

    // the references to all methods are exposed, so you can iterate
    // over all of them
    for method_id in dex.get_method_ids() {
        // ...
    }

    // NOTE: the result of num_method_ids is the number given in the
    // file header, NOT the length of get_method_ids.
    assert_eq!(dex.num_method_ids() as usize, dex.get_method_ids().len());
    Ok(())
}

fn dex_get_field(dex: &DexFile<'_>) -> Result<()> {
    // the interface for fields is pretty much the same as for methods
    let field_id = dex.get_field_id(0)?;
    assert!(dex.field_id_idx(field_id)? == 0);

    // same as for methods
    let name = dex.get_utf16_str_at(field_id.name_idx)?;
    let type_name = dex.get_type_desc_utf16_at(field_id.type_idx)?;
    let class_name = dex.get_type_desc_utf16_at(field_id.class_idx)?;

    // prettified version is also available
    let pretty_field = dex.pretty_field_opt(field_id, prettify::Field::WithType)?;
    // the '_opt' method will return an error on invalid input or if the string
    // can't be created. However, if you want to get a string regardless of the
    // input, just use:
    let pretty_field = dex.pretty_field(field_id, prettify::Field::WithType);

    // all fields are exposed, so you can iterate over them
    for field_id in dex.get_field_ids() {
        // ...
    }
    Ok(())
}

fn dex_types(dex: &DexFile<'_>) -> Result<()> {
    // types are somewhat different from methods and fields as they are just references
    // to their names in the string ids section.
    let type_id = dex.get_type_id(0)?;
    assert!(dex.type_id_idx(type_id)? == 0);

    // name can be retrieved in various ways
    let name = dex.get_type_desc_utf16(type_id)?;
    // see dex_strings.rs for more examples on the strings used in dex files
    let name = dex.get_type_desc_utf16_lossy(type_id)?;

    // you can even skip all verification and get the string as
    // fast as possible
    let string_id = dex.get_string_id(type_id.descriptor_idx)?;
    let name = unsafe { dex.fast_get_utf8_str(string_id)? };

    // same as above, all types are exposed
    for _ in dex.get_type_ids() {}
    Ok(())
}

fn main() {
    // ...
}
