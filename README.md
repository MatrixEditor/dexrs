# DEXrs

**DEXrs** is an exploratory project in Rust aimed at developing a decompiler for Android executable files (DEX files).

#### What this project already covers:

- [x] A (*blazingly fast*) DEX file parser using lazy parsing
- [x] A simple disassembler for Dalvik byte code
- [x] A simplistic Smali decompiler

#### Roadmap

- [ ] Basic Java decompiler
- [ ] Bytecode modification and DEX rebuild


## Installation


Install DEXrs using Cargo:
```bash
cargo install --git https://github.com/MatrixEditor/dexrs dexrs
```

## Usage

### Disassembling DEX files

Here’s a quick example of how to disassemble a DEX file:

```rust
let mut f = File::open("classes.dex").expect("file not found");
// parse DEX input and verify its contents
let mut dex = Dex::read(&mut f, true)?;

let class = dex.get_class_def(0)?;
if let Some(method) = class.get_direct_method(0) {
    for insn in method.disasm(&mut dex)? {
        println!("    {:#06x}: {:?}", insn.range.start, insn);
    }
}
```

## Decompilation to Smali

```rust
use dexrs::smali::SmaliWrite;

let mut f = File::open("classes.dex").expect("file not found");
let mut dex = Dex::read(&mut f, true)?;

let class = dex.get_class_def(0)?;
let mut stdout = std::io::stdout();
stdout.write_class(&class, &mut dex)?;
```

## License

This project is licensed under the [MIT license](LICENSE)