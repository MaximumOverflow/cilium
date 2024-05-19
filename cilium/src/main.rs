use cilium::raw::heaps::table::{AssemblyTable, TableHeap};
use cilium::raw::assembly::Assembly;
use cilium::raw::FromByteStream;
use cilium::raw::pe::PEFile;
use std::io::Cursor;

fn main() {
    let pe = {
        let bytes = std::fs::read("TestAssembly.dll").unwrap();
        let mut cursor = Cursor::new(bytes.as_slice());
        PEFile::read(&mut cursor, &()).unwrap()
    };
    let assembly = Assembly::try_from(pe).unwrap();
    let tables = assembly.metadata_root().get_heap::<TableHeap>().unwrap();
    let _table =  tables.get_table::<AssemblyTable>().unwrap();
}
