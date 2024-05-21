use crate::raw::indices::metadata_token::{MetadataToken, String as StringToken};
use std::fmt::{Debug, Display, Formatter};
use std::collections::HashMap;
use std::alloc::Layout;
use fxhash::FxHashMap;
use std::ops::Deref;
use bumpalo::Bump;
use crate::raw::heaps::BlobIndex;
use crate::schema::r#type::TypePool;

pub(crate) struct StringHeap<'l> {
	bump: &'l Bump,
	offset: usize,
	vec: Vec<(&'l str, MetadataToken)>,
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

	pub fn intern(&mut self, str: &str) -> &'l str {
		if let Some(idx) = self.map.get(str) {
			return self.vec[*idx].0;
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
		self.vec.push((interned, StringToken(offset).into()));
		self.map.insert(interned, idx);
		interned
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

pub(crate) struct BlobHeap<'l> {
	bump: &'l Bump,
	offset: usize,
	vec: Vec<InternedBlob<'l>>,
	map: FxHashMap<&'l [u8], usize>,
}

impl<'l> BlobHeap<'l> {
	pub fn new(bump: &'l Bump) -> Self {
		Self {
			bump,
			offset: 0,
			vec: vec![],
			map: HashMap::default(),
		}
	}

	pub fn intern(&mut self, blob: &[u8]) -> InternedBlob<'l> {
		if let Some(idx) = self.map.get(blob) {
			return self.vec[*idx];
		}

		let (interned, offset) = { // Allocate str + zero termination character
			let interned = self.bump.alloc_slice_copy(blob);
			let new_offset = self.offset + blob.len();
			let offset = std::mem::replace(&mut self.offset, new_offset);
			(interned, offset)
		};

		let idx = self.vec.len();
		let blob = InternedBlob(interned, BlobIndex(offset).into());
		self.vec.push(blob);
		self.map.insert(interned, idx);
		blob
	}
}

impl Debug for BlobHeap<'_> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		use std::fmt::Write;
		let mut dbg = f.debug_struct("BlobHeap");
		let mut name = String::new();
		for blob in &self.vec {
			name.clear();
			write!(name, "{:X}", blob.1.0)?;
			dbg.field(&name, &blob.0);
		}
		dbg.finish()
	}
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct InternedBlob<'l>(&'l [u8], BlobIndex);

impl Deref for InternedBlob<'_> {
	type Target = [u8];
	#[inline]
	fn deref(&self) -> &Self::Target {
		self.0
	}
}

impl Debug for InternedBlob<'_> {
	#[inline]
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		write!(f, "[u8; ")?;
		Debug::fmt(&self.0.len(), f)?;
		write!(f, "]")
	}
}

impl InternedBlob<'_> {
	#[inline]
	pub fn index(&self) -> BlobIndex {
		self.1
	}
}

pub struct DataPool<'l> {
	bump: &'l Bump,
	types: TypePool<'l>,
}

impl<'l> DataPool<'l> {
	pub fn new(bump: &'l Bump) -> Self {
		Self {
			bump,
			types: TypePool::new(bump),
		}
	}

	pub(crate) fn bump(&self) -> &'l Bump {
		self.bump
	}

	pub(crate) fn types(&self) -> &TypePool<'l> {
		&self.types
	}
}
