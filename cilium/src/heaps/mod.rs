use std::io::{Cursor, ErrorKind, Read, Seek};
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use owning_ref::ArcRef;
use crate::heaps::blob::BlobHeap;
use crate::heaps::guid::GuidHeap;
use crate::heaps::string::{StringHeap, UserStringHeap};

use crate::heaps::table::TableHeap;
use crate::indices::sizes::{BlobIndexSize, GuidIndexSize, StringIndexSize};
use crate::utilities::{FromByteStream, read_string_from_stream_into};

pub mod table;
mod guid;
mod string;
mod blob;

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

		let offset = u32::read(stream, &())? as usize;
		let size = u32::read(stream, &())? as usize;

		let mut name = [0u8; 32];
		let name = read_string_from_stream_into::<4>(stream, name.as_mut_slice())?;

		let range = offset..offset + size;
		let data = data.clone().map(|s| &s[range]);

		match name {
			"#Blob" => Ok(Arc::new(BlobHeap::from(data))),
			"#US" => Ok(Arc::new(UserStringHeap::from(data))),
			"#~" => Ok(Arc::new(TableHeap::try_from(data)?)),
			"#GUID" => Ok(Arc::new(GuidHeap::try_from(data)?)),
			"#Strings" => Ok(Arc::new(StringHeap::try_from(data)?)),
			_ => unimplemented!("Unimplemented MetadataHeap kind {:?}", name),
		}
	}
}


#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StringIndex(usize);

impl FromByteStream for StringIndex {
	type Deps = StringIndexSize;
	fn read(stream: &mut Cursor<&[u8]>, size: &Self::Deps) -> std::io::Result<Self> {
		let mut value = 0usize.to_ne_bytes();
		stream.read_exact(&mut value[..size.0])?;
		Ok(Self(usize::from_le_bytes(value)))
	}
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct BlobIndex(usize);

impl FromByteStream for BlobIndex {
	type Deps = BlobIndexSize;
	fn read(stream: &mut Cursor<&[u8]>, size: &Self::Deps) -> std::io::Result<Self> {
		let mut value = 0usize.to_ne_bytes();
		stream.read_exact(&mut value[..size.0])?;
		Ok(Self(usize::from_le_bytes(value)))
	}
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct GuidIndex(usize);

impl FromByteStream for GuidIndex {
	type Deps = GuidIndexSize;
	fn read(stream: &mut Cursor<&[u8]>, size: &Self::Deps) -> std::io::Result<Self> {
		let mut value = 0usize.to_ne_bytes();
		stream.read_exact(&mut value[..size.0])?;
		Ok(Self(usize::from_le_bytes(value)))
	}
}

pub(super) struct SizeDebugWrapper(usize);
impl Debug for SizeDebugWrapper {
	#[inline]
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		f.write_str("[u8; ")?;
		Debug::fmt(&self.0, f)?;
		f.write_str("]")
	}
}
