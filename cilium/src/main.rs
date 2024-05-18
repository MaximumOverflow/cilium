use std::io::Cursor;
use crate::assembly::Assembly;
use crate::pe::PEFile;
use crate::utilities::FromByteStream;

mod pe;
mod assembly;
mod utilities;
mod indices;
mod heaps;

fn main() {
    let bytes = std::fs::read("TestAssembly.dll").unwrap();
    let mut cursor = Cursor::new(bytes.as_slice());
    let pe = PEFile::read(&mut cursor).unwrap();
    let assembly = Assembly::try_from(pe).unwrap();
    dbg!(assembly);
}
