use std::io::{Cursor, ErrorKind, Read};
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

pub use crate::raw::heaps::blob::BlobHeap;
pub use crate::raw::heaps::guid::GuidHeap;
pub use crate::raw::heaps::string::{StringHeap, UserStringHeap};

use crate::raw::heaps::table::TableHeap;
use crate::raw::indices::metadata_token;
use crate::raw::indices::sizes::IndexSizes;
use crate::utilities::{FromByteStream, read_string_from_stream_into};

pub mod table;
pub mod guid;
pub mod string;
pub mod blob;

#[derive(Debug)]
pub enum MetadataHeap<'l> {
	Blob(BlobHeap<'l>),
	Guid(GuidHeap<'l>),
	Table(TableHeap<'l>),
	String(StringHeap<'l>),
	UserString(UserStringHeap<'l>),
}

impl<'l> MetadataHeap<'l> {
	#[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
	pub fn read(stream: &mut Cursor<&'l [u8]>, data: &'l [u8]) -> std::io::Result<Arc<Self>> {
		if stream.get_ref().as_ptr() != data.as_ptr() {
			return Err(ErrorKind::InvalidInput.into());
		}

		let offset = u32::read(stream, &())? as usize;
		let size = u32::read(stream, &())? as usize;

		let mut name = [0u8; 32];
		let name = read_string_from_stream_into::<4>(stream, name.as_mut_slice())?;
		let data = &data[offset..offset + size];

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

#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StringIndex(pub usize);

impl FromByteStream for StringIndex {
	type Deps = IndexSizes;
	fn read(stream: &mut Cursor<&[u8]>, sizes: &Self::Deps) -> std::io::Result<Self> {
		let mut value = 0usize.to_ne_bytes();
		stream.read_exact(&mut value[..sizes.string])?;
		Ok(Self(usize::from_le_bytes(value)))
	}
}

impl From<StringIndex> for metadata_token::StringToken {
	#[inline]
	fn from(value: StringIndex) -> Self {
		Self(value.0)
	}
}

impl From<StringIndex> for metadata_token::MetadataToken {
	#[inline]
	fn from(value: StringIndex) -> Self {
		metadata_token::StringToken(value.0).into()
	}
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct BlobIndex(pub usize);

impl FromByteStream for BlobIndex {
	type Deps = IndexSizes;
	fn read(stream: &mut Cursor<&[u8]>, sizes: &Self::Deps) -> std::io::Result<Self> {
		let mut value = 0usize.to_ne_bytes();
		stream.read_exact(&mut value[..sizes.blob])?;
		Ok(Self(usize::from_le_bytes(value)))
	}
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct GuidIndex(pub usize);

impl FromByteStream for GuidIndex {
	type Deps = IndexSizes;
	fn read(stream: &mut Cursor<&[u8]>, sizes: &Self::Deps) -> std::io::Result<Self> {
		let mut value = 0usize.to_ne_bytes();
		stream.read_exact(&mut value[..sizes.guid])?;
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
