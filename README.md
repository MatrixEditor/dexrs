# DEXrs

**DEXrs** is a Rust library and CLI tool for parsing, inspecting, and modifying Android DEX files. It covers a zero-copy parser, a Dalvik disassembler, a full-featured terminal UI, a DEX modification API, and Python bindings via PyO3.

<img width="1017" height="470" alt="image" src="https://github.com/user-attachments/assets/4823aacb-650c-482a-9373-974ed76375a7" />


#### What this project covers

- [x] Zero-copy, lazy DEX file parser (fuzzing-hardened)
- [x] Dalvik bytecode disassembler
- [x] `dexrs` CLI — 12 subcommands for inspection and modification
- [x] Interactive TUI (`dexrs inspect`) via ratatui/crossterm
- [x] DEX modification API — in-place patching and structural editing
- [x] Python extension via PyO3 (parser + editor)
- [ ] Benchmarks (WIP)
- [ ] Smali disassembler / decompiler




## Installation

```bash
# CLI binary
cargo install --git https://github.com/MatrixEditor/dexrs dexrs
# with TUI
cargo install --git https://github.com/MatrixEditor/dexrs -F tui dexrs

# Python package
pip install -v git+https://github.com/MatrixEditor/dexrs@dev/v2-rewrite
```


## CLI — `dexrs`

```
dexrs [--no-color] [--no-verify] [--json] <COMMAND> <FILE> [OPTIONS]
```

### Inspection

| Command | Description |
|---|---|
| `info` | File header, integrity hashes, section counts |
| `map` | Map list — all section types and their offsets |
| `classes` | All class definitions with access flags |
| `class --class <NAME>` | Single class (fields + methods) |
| `methods` | All methods across all classes |
| `fields` | All fields across all classes |
| `disasm --class <C> --method <M>` | Disassemble one method |
| `strings` | Full string pool |
| `types` | All type descriptors |
| `inspect` | Interactive TUI (see below) |

```bash
dexrs info    classes.dex
dexrs classes classes.dex --no-color
dexrs class   classes.dex --class LMain;
dexrs disasm  classes.dex --class LMain; --method main --json
```

### Modification

#### `patch` — in-place (overwrites source file)

```bash
# Set class access flags
dexrs patch flags <FILE> --class <CLASS> --flags <HEX>

# Overwrite a single instruction word
dexrs patch insn <FILE> --offset <HEX_OFFSET> --pc <CODE_UNIT> --word <HEX>
```

```bash
dexrs patch flags classes.dex --class LMain; --flags 0x11   # public final
```

#### `edit` — structural (writes to `--output`)

```bash
dexrs edit rename-class    <FILE> <OLD> <NEW>            --output <OUT>
dexrs edit set-flags       <FILE> --class <C> --flags <F> --output <OUT>
dexrs edit set-method-flags <FILE> --class <C> --method <M> --flags <F> --output <OUT>
dexrs edit clear-hiddenapi <FILE>                        --output <OUT>
```

```bash
dexrs edit rename-class classes.dex LMain; LRenamedMain; --output out.dex
dexrs edit set-flags    classes.dex --class LMain; --flags 0x21 --output out.dex
```


## Rust API

### Parsing

```rust
use dexrs::file::{verifier::VerifyPreset, DexFile, DexFileContainer, DexLocation};

// From a file with verification
let file = std::fs::File::open("classes.dex")?;
let dex = DexFileContainer::new(&file)
    .verify(true)
    .verify_checksum(true)
    .open()?;

// From memory
let dex = DexFile::open(data, DexLocation::InMemory, VerifyPreset::None)?;
```

See `examples/parse_dex_file.rs` and `examples/dex_basic_ops.rs` for full usage.

### DEX modification — `DexEditor`

`DexEditor` owns the DEX bytes and exposes named mutations. Finalise with
`build()` -> `Vec<u8>` or `write_to(path)` — both recalculate the Adler32 checksum.

```rust
use std::path::Path;
use dexrs::file::DexEditor;

let mut editor = DexEditor::from_file(Path::new("classes.dex"))?;
// or: DexEditor::from_bytes(bytes)?

// Accepts dotted ("com.example.Foo"), slash, or descriptor ("Lcom/example/Foo;") form
editor.set_class_access_flags("LMain;", 0x0011 /* public final */)?;
editor.rename_class("LMain;", "LRenamedMain;")?;
editor.set_method_access_flags("LMain;", "main", 0x0009 /* public static */)?;
editor.clear_hiddenapi_flags().ok(); // no-op if section absent

// Finalise
let bytes: Vec<u8> = editor.build()?;
// or:
editor.write_to(Path::new("out.dex"))?;
```

### Low-level checksum

```rust
use dexrs::file::patch::update_checksum;

let mut raw = std::fs::read("classes.dex")?;
// ... raw byte mutations ...
update_checksum(&mut raw);  // recalculate Adler32 in-place
```

See `examples/dex_edit.rs` for a complete runnable example.


## Python API

### Parsing

```python
from dexrs import DexFile, VerifyPreset, FileDexContainer

container = FileDexContainer("classes.dex")
dex = DexFile.from_container(container, verify=VerifyPreset.All)

for cls in dex.get_class_defs():
    print(cls)
```

### DEX modification — `DexEditor`

```python
from dexrs import DexEditor

editor = DexEditor.from_file("classes.dex")
# or: DexEditor.from_bytes(open("classes.dex","rb").read())

editor.set_class_access_flags("LMain;", 0x0001)          # public
editor.rename_class("LMain;", "LRenamedMain;")           # rebuild string pool
editor.set_method_access_flags("LMain;", "main", 0x0009) # public static
editor.clear_hiddenapi_flags()                           # strip hidden-API metadata

# Get bytes
data = editor.build()
open("out.dex", "wb").write(data)

# Or write directly (editor is consumed)
editor.write_to("out.dex")
```

#### Common access flag values

| Value | Meaning |
|---|---|
| `0x0001` | `public` |
| `0x0002` | `private` |
| `0x0004` | `protected` |
| `0x0008` | `static` |
| `0x0010` | `final` |
| `0x0100` | `native` |
| `0x0400` | `abstract` |
| `0x1000` | `synthetic` |


## License

This project is licensed under the [MIT license](LICENSE).
