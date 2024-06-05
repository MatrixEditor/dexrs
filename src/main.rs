use dexrs::dalvik::error::Result;
use dexrs::dalvik::file::{Dex, DexClassDef, IDex};
use dexrs::smali::SmaliWrite;
use std::fs::File;
use std::rc::Rc;

fn main() -> Result<()> {
    let mut f = File::open("tests/prime/prime.dex")?;
    let mut dex: Dex<File> = Dex::read(&mut f, true)?;

    let mut stdout = std::io::stdout();
    for i in 0..dex.header.class_defs_size {
        let class: Rc<DexClassDef> = dex.get_class_def(i)?;
        stdout.write_class(&class, &mut dex)?;
    }

    Ok(())
}
