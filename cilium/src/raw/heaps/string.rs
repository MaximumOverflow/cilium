use std::fmt::{Debug, Formatter};
use std::io::{Error, ErrorKind};

use owning_ref::ArcRef;

use crate::raw::heaps::{SizeDebugWrapper, StringIndex};

pub struct StringHeap {
	data: ArcRef<[u8]>,
}

impl TryFrom<ArcRef<[u8]>> for StringHeap {
	type Error = Error;
	fn try_from(data: ArcRef<[u8]>) -> Result<Self, Self::Error> {
		match data.as_ref() {
			[0, ..] => Ok(Self { data }),
			_ => Err(ErrorKind::InvalidData.into()),
		}
	}
}

impl StringHeap {
	pub fn get(&self, idx: StringIndex) -> Option<&str> {
		let slice = self.data.as_ref().get(idx.0..)?;
		let end = slice.iter().position(|c| *c == 0)?;
		std::str::from_utf8(&slice[..end]).ok()
	}
}

impl Debug for StringHeap {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		let mut dbg = f.debug_struct("StringHeap");
		dbg.field("data", &SizeDebugWrapper(self.data.len()));
		dbg.finish()
	}
}

pub struct UserStringHeap {
	data: ArcRef<[u8]>,
}

impl From<ArcRef<[u8]>> for UserStringHeap {
	fn from(data: ArcRef<[u8]>) -> Self {
		Self { data }
	}
}

impl Debug for UserStringHeap {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		let mut dbg = f.debug_struct("UserStringHeap");
		dbg.field("data", &SizeDebugWrapper(self.data.len()));
		dbg.finish()
	}
}
