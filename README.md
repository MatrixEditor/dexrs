# DEXrs

**DEXrs** is an exploratory project in Rust aimed at developing a decompiler for Android executable files (DEX files). It currently covers a low level DEX file parser and disassembler with a Python API.

#### What this project already covers:

- [x] A (*blazingly fast* 🔥) DEX file parser that utilizes
    - [x] *zero-copy* wherever applicable
    - [x] *lazy-parsing* all the time
    - [x] respect fuzzing tests to make sure there's no panic
- [x] Python extension using pyo3 for Pythonists
- [x] A simple disassembler for Dalvik byte code
- [ ] Benchmarks are WIP, but present
- [ ] A simplistic Smali disassembler

#### Roadmap

- [ ] Basic Java decompiler
- [ ] Bytecode modification and DEX rebuild


## Installation


Install DEXrs using Cargo:
```bash
cargo install --git https://github.com/MatrixEditor/dexrs dexrs
```

Or directly using pip:
```bash
pip install -ve dexrs@git+https://github.com/MatrixEditor/dexrs.git
```

## Usage

### Disassembling DEX files

Here’s a quick example of how to parse a DEX file:

```rust
let mut f = File::open("classes.dex").expect("file not found");
// parse DEX input and verify its contents
let container = DexFileContainer::new(&file)
    .verify(true)
    .verify_checksum(true);

// please use the examples/ directory for more usage information
let dex = container.open()?;
```

In-memory parsing is also allowed:
```rust
let data: [u8] = ...;
let dex = DexFile::open(&data, DexLocation::InMemory, VerifyPreset::All)?;
```

## License

This project is licensed under the [MIT license](LICENSE)