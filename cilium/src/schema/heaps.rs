use crate::raw::indices::metadata_token::{MetadataToken, String as StringToken};
use std::collections::HashMap;
use std::alloc::Layout;
use std::fmt::{Debug, Display, Formatter};
use std::ops::Deref;
use bumpalo::Bump;
use fxhash::FxHashMap;

pub(crate) struct StringHeap<'l> {
	bump: &'l Bump,
	offset: usize,
	vec: Vec<InternedString<'l>>,
	map: FxHashMap<&'l str, usize>,
}

impl<'l> StringHeap<'l> {
	pub fn new(bump: &'l Bump) -> Self {
		let mut heap = Self {
			bump,
			offset: 0,
			vec: vec![],
			map: HashMap::default(),
		};
		heap.intern("");
		heap
	}

	pub fn intern(&mut self, str: &str) -> InternedString<'l> {
		if let Some(idx) = self.map.get(str) {
			return self.vec[*idx];
		}

		let (interned, offset) = unsafe { // Allocate str + zero termination character
			let layout = Layout::array::<u8>(str.len() + 1).unwrap();
			let ptr = self.bump.alloc_layout(layout);
			let interned = std::slice::from_raw_parts_mut(ptr.as_ptr(), layout.size());
			interned[..str.len()].copy_from_slice(str.as_bytes());
			interned[str.len()] = 0;
			let str = std::str::from_utf8_unchecked(&interned[..str.len()]);
			let new_offset = self.offset + layout.size();
			let offset = std::mem::replace(&mut self.offset, new_offset);
			(str, offset)
		};

		let idx = self.vec.len();
		let string = InternedString(interned, StringToken(offset).into());
		self.vec.push(string);
		self.map.insert(interned, idx);
		string
	}
}

impl Debug for StringHeap<'_> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		use std::fmt::Write;
		let mut dbg = f.debug_struct("StringHeap");
		let mut name = String::new();
		for str in &self.vec {
			name.clear();
			write!(name, "{:X}", str.1.raw())?;
			dbg.field(&name, &str.0);
		}
		dbg.finish()
	}
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct InternedString<'l>(&'l str, MetadataToken);

impl Deref for InternedString<'_> {
	type Target = str;
	#[inline]
	fn deref(&self) -> &Self::Target {
		self.0
	}
}

impl Display for InternedString<'_> {
	#[inline]
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		Display::fmt(self.0, f)
	}
}

impl InternedString<'_> {
	#[inline]
	pub fn metadata_token(&self) -> MetadataToken {
		self.1
	}
}
