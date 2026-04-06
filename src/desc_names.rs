pub fn pretty_desc(desc: &str) -> String {
    let dim = desc.chars().filter(|c| *c == '[').count();
    let name = &desc[dim..];
    let mut output = String::new();

    if name.starts_with("L") {
        let end_idx = if name.ends_with(";") {
            name.len() - 1
        } else {
            name.len()
        };
        output.push_str(&name[1..end_idx].replace("/", "."));
    } else {
        output.push_str(match name.as_bytes()[0] {
            b'B' => "byte",
            b'C' => "char",
            b'D' => "double",
            b'F' => "float",
            b'I' => "int",
            b'J' => "long",
            b'S' => "short",
            b'Z' => "boolean",
            b'V' => "void",
            _ => name,
        });
    }

    if dim > 0 {
        output.push_str(&"[]".repeat(dim));
    }
    output
}
