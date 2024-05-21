use std::fmt::{Debug, Formatter};
use std::io::Cursor;

use crate::raw::heaps::{BlobIndex, SizeDebugWrapper};
use crate::utilities::read_compressed_u32;

#[derive(Copy, Clone)]
pub struct BlobHeap<'l> {
	data: &'l [u8],
}

impl<'l> BlobHeap<'l> {
	pub fn get(&self, idx: BlobIndex) -> Option<&'l [u8]> {
		match idx.0 {
			0 => None,
			_ => {
				let bytes = &self.data[idx.0..];
				let mut cursor = Cursor::new(bytes);
				let len = read_compressed_u32(&mut cursor).ok()? as usize;
				Some(&bytes[cursor.position() as usize..cursor.position() as usize + len])
			}
		}
	}
}

impl<'l> From<&'l [u8]> for BlobHeap<'l> {
	fn from(data: &'l [u8]) -> Self {
		Self { data }
	}
}

impl Debug for BlobHeap<'_> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		let mut dbg = f.debug_struct("BlobHeap");
		dbg.field("data", &SizeDebugWrapper(self.data.len()));
		dbg.finish()
	}
}
