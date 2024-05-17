use crate::pe::{PEFile, PEHeader};

mod pe;

fn main() {
    let bytes = std::fs::read("target/debug/cilium.exe").unwrap();
    let pe = PEFile::try_from(bytes.as_slice()).unwrap();
    println!("{pe:#X?}");
}
