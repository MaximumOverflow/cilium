use std::fmt::{Debug, Formatter};
use crate::raw::heaps::{GuidIndex};
use std::io::{Error, ErrorKind};
use owning_ref::ArcRef;
use std::mem::size_of;
use uuid::Uuid;

pub struct GuidHeap {
	data: ArcRef<[u8]>,
}

impl TryFrom<ArcRef<[u8]>> for GuidHeap {
	type Error = Error;
	fn try_from(data: ArcRef<[u8]>) -> Result<Self, Self::Error> {
		match data.len() % size_of::<Uuid>() == 0 {
			true => Ok(Self { data }),
			false => Err(ErrorKind::InvalidData.into()),
		}
	}
}

#[allow(clippy::len_without_is_empty)]
impl GuidHeap {
	pub fn len(&self) -> usize {
		self.data.len() / size_of::<Uuid>()
	}

	pub fn get(&self, idx: GuidIndex) -> Option<Uuid> {
		match idx.0 {
			0 => None,
			_ => {
				let offset = (idx.0 - 1) * size_of::<Uuid>();
				let bytes = self.data.get(offset..offset + size_of::<Uuid>())?;
				Some(Uuid::from_slice_le(bytes).unwrap())
			},
		}
	}

	pub fn guids(&self) -> impl Iterator<Item = Uuid> + '_ {
		(1..=self.len()).map(|i| self.get(GuidIndex(i)).unwrap())
	}
}

impl Debug for GuidHeap {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		f.write_str("GuidHeap ")?;
		let mut dbg = f.debug_list();
		for guid in self.guids() {
			dbg.entry(&guid);
		}
		dbg.finish()
	}
}
