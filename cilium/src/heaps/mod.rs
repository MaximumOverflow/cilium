use std::io::{Cursor, ErrorKind, Read, Seek};
use std::fmt::Debug;
use std::sync::Arc;

use owning_ref::ArcRef;

use crate::heaps::table::TableHeap;
use crate::utilities::{FromByteStream, read_string_from_stream_into};

pub mod table;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum MetadataHeapKind {
	Blob,
	GUID,
	Table,
	String,
	UserString,
}

pub trait MetadataHeap: Debug {
	fn name(&self) -> &str;
	fn data(&self) -> &[u8];
	fn kind(&self) -> MetadataHeapKind;
}

impl dyn MetadataHeap {
	pub fn read(stream: &mut Cursor<&[u8]>, data: &ArcRef<[u8]>) -> std::io::Result<Arc<Self>> {
		if stream.get_ref().as_ptr() != data.as_ptr() {
			return Err(ErrorKind::InvalidInput.into());
		}

		let offset = u32::read(stream)? as usize;
		let size = u32::read(stream)? as usize;

		let mut name = [0u8; 32];
		let name = read_string_from_stream_into::<4>(stream, name.as_mut_slice())?;

		let range = offset..offset + size;
		let data = data.clone().map(|s| &s[range]);

		match name {
			"#~" => Ok(Arc::new(TableHeap::try_from(data)?)),
			_ => unimplemented!("Unimplemented MetadataHeap kind {:?}", name),
		}
	}
}


macro_rules! declare_heap_index {
    ($($ident: ident),*) => {$(
		#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
		pub struct $ident(usize);

		impl $ident {
			pub fn read(stream: &mut Cursor<&[u8]>, size: usize) -> std::io::Result<Self> {
				let mut value = 0usize.to_ne_bytes();
				stream.read_exact(&mut value[..size])?;
				Ok(Self(usize::from_le_bytes(value)))
			}
		}
	)*};
}

declare_heap_index!(StringIndex, BlobIndex, GuidIndex);

