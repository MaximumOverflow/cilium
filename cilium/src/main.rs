use std::io::Cursor;
use std::time::Duration;
use crate::assembly::Assembly;
use crate::pe::PEFile;
use crate::utilities::FromByteStream;

mod pe;
mod assembly;
mod utilities;
mod indices;
mod heaps;

fn main() {
    let pe = {
        let bytes = std::fs::read("TestAssembly.dll").unwrap();
        let mut cursor = Cursor::new(bytes.as_slice());
        PEFile::read(&mut cursor, &()).unwrap()
    };
    let assembly = Assembly::try_from(pe).unwrap();
}
