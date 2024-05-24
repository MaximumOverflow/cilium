use std::fmt::{Debug, Formatter};
use std::io::{Error, ErrorKind};
use std::mem::size_of;

use uuid::Uuid;
use crate::ffi::containers::Slice;

use crate::raw::heaps::GuidIndex;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct GuidHeap<'l> {
	data: Slice<'l, u8>,
}

impl<'l> TryFrom<&'l [u8]> for GuidHeap<'l> {
	type Error = Error;
	fn try_from(data: &'l [u8]) -> Result<Self, Self::Error> {
		match data.len() % size_of::<Uuid>() == 0 {
			true => Ok(Self { data: data.into() }),
			false => Err(ErrorKind::InvalidData.into()),
		}
	}
}

#[allow(clippy::len_without_is_empty)]
impl GuidHeap<'_> {
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

impl Debug for GuidHeap<'_> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		f.write_str("GuidHeap ")?;
		let mut dbg = f.debug_list();
		for guid in self.guids() {
			dbg.entry(&guid);
		}
		dbg.finish()
	}
}

pub(crate) mod ffi {
	use uuid::Uuid;
	use crate::raw::heaps::{GuidHeap, GuidIndex};

	#[no_mangle]
	pub unsafe extern fn cilium_raw_GuidHeap_get(
		heap: &GuidHeap,
		idx: GuidIndex,
		out_guid: &mut Uuid,
	) -> bool {
		match heap.get(idx) {
			None => false,
			Some(guid) => {
				*out_guid = guid;
				true
			}
		}
	}
}
