use std::io::{Cursor, ErrorKind, Read};
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use owning_ref::ArcRef;
pub use crate::raw::heaps::blob::BlobHeap;
pub use crate::raw::heaps::guid::GuidHeap;
pub use crate::raw::heaps::string::{StringHeap, UserStringHeap};

use crate::raw::heaps::table::TableHeap;
use crate::raw::indices::sizes::{BlobIndexSize, GuidIndexSize, StringIndexSize};
use crate::utilities::{FromByteStream, read_string_from_stream_into};

pub mod table;
mod guid;
mod string;
mod blob;

#[derive(Debug)]
pub enum MetadataHeap {
	Blob(BlobHeap),
	Guid(GuidHeap),
	Table(TableHeap),
	String(StringHeap),
	UserString(UserStringHeap),
}

impl MetadataHeap {
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
			"#Blob" => Ok(Arc::new(Self::Blob(BlobHeap::from(data)))),
			"#US" => Ok(Arc::new(Self::UserString(UserStringHeap::from(data)))),
			"#~" => Ok(Arc::new(Self::Table(TableHeap::try_from(data)?))),
			"#GUID" => Ok(Arc::new(Self::Guid(GuidHeap::try_from(data)?))),
			"#Strings" => Ok(Arc::new(Self::String(StringHeap::try_from(data)?))),
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

pub(crate) struct SizeDebugWrapper(usize);
impl Debug for SizeDebugWrapper {
	#[inline]
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		f.write_str("[u8; ")?;
		Debug::fmt(&self.0, f)?;
		f.write_str("]")
	}
}
