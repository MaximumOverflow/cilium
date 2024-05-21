use std::fmt::{Debug, Formatter};
use std::io::{Error, ErrorKind};

use crate::raw::heaps::{SizeDebugWrapper, StringIndex};

#[derive(Copy, Clone)]
pub struct StringHeap<'l> {
	data: &'l [u8],
}

impl<'l> TryFrom<&'l [u8]> for StringHeap<'l> {
	type Error = Error;
	fn try_from(data: &'l [u8]) -> Result<Self, Self::Error> {
		match data.as_ref() {
			[0, ..] => Ok(Self { data }),
			_ => Err(ErrorKind::InvalidData.into()),
		}
	}
}

impl<'l> StringHeap<'l> {
	pub fn get(&self, idx: StringIndex) -> Option<&'l str> {
		let slice = self.data.as_ref().get(idx.0..)?;
		let end = slice.iter().position(|c| *c == 0)?;
		std::str::from_utf8(&slice[..end]).ok()
	}
}

impl Debug for StringHeap<'_> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		let mut dbg = f.debug_struct("StringHeap");
		dbg.field("data", &SizeDebugWrapper(self.data.len()));
		dbg.finish()
	}
}

pub struct UserStringHeap<'l> {
	data: &'l [u8],
}

impl<'l> From<&'l [u8]> for UserStringHeap<'l> {
	fn from(data: &'l [u8]) -> Self {
		Self { data }
	}
}

impl Debug for UserStringHeap<'_> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		let mut dbg = f.debug_struct("UserStringHeap");
		dbg.field("data", &SizeDebugWrapper(self.data.len()));
		dbg.finish()
	}
}
