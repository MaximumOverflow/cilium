use crate::heaps::{MetadataHeap, MetadataHeapKind, SizeDebugWrapper};
use std::fmt::{Debug, Formatter};
use owning_ref::ArcRef;

pub struct BlobHeap {
	data: ArcRef<[u8]>,
}

impl From<ArcRef<[u8]>> for BlobHeap {
	fn from(data: ArcRef<[u8]>) -> Self {
		Self { data }
	}
}

impl MetadataHeap for BlobHeap {
	fn name(&self) -> &str {
		"#Blob"
	}

	fn data(&self) -> &[u8] {
		self.data.as_ref()
	}

	fn kind(&self) -> MetadataHeapKind {
		MetadataHeapKind::Blob
	}
}

impl Debug for BlobHeap {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		let mut dbg = f.debug_struct("BlobHeap");
		dbg.field("data", &SizeDebugWrapper(self.data.len()));
		dbg.finish()
	}
}