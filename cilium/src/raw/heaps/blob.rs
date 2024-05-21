use crate::raw::heaps::{BlobIndex, SizeDebugWrapper};
use crate::utilities::read_compressed_u32;
use std::fmt::{Debug, Formatter};
use owning_ref::ArcRef;
use std::io::Cursor;

pub struct BlobHeap {
	data: ArcRef<[u8]>,
}

impl BlobHeap {
	pub fn get(&self, idx: BlobIndex) -> Option<&[u8]> {
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

impl From<ArcRef<[u8]>> for BlobHeap {
	fn from(data: ArcRef<[u8]>) -> Self {
		Self { data }
	}
}

impl Debug for BlobHeap {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		let mut dbg = f.debug_struct("BlobHeap");
		dbg.field("data", &SizeDebugWrapper(self.data.len()));
		dbg.finish()
	}
}
