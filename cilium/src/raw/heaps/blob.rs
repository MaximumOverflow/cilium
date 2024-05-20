use crate::raw::heaps::SizeDebugWrapper;
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

impl Debug for BlobHeap {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		let mut dbg = f.debug_struct("BlobHeap");
		dbg.field("data", &SizeDebugWrapper(self.data.len()));
		dbg.finish()
	}
}

/// These are used extensively in metadata signature blobs.
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum TypeSignatureTag {
	/// Marks end of a list.
	End = 0x00,
	Void = 0x01,
	Bool = 0x02,
	Char = 0x03,
	Int1 = 0x04,
	UInt1 = 0x05,
	Int2 = 0x06,
	UInt2 = 0x07,
	Int4 = 0x08,
	UInt4 = 0x09,
	Int8 = 0x0a,
	UInt8 = 0x0b,
	Float = 0x0c,
	Double = 0x0d,
	String = 0x0e,
	/// Followed by type.
	Pointer = 0x0f,
	/// Followed by type.
	Reference = 0x10,
	/// Followed by TypeDef or TypeRef token.
	ValueType = 0x11,
	/// Followed by TypeDef or TypeRef token.
	ClassType = 0x12,
	/// Generic parameter in a generic type definition, represented as number (compressed unsigned integer).
	GenericParam = 0x13,
	/// Followed by: type, rank, boundsCount, \[bounds...], loCount, \[lo...].
	Array = 0x14,
	/// Generic type instantiation. Followed by type type-arg-count type-1 ... type-n.
	GenericInst = 0x15,
	/// Undocumented
	TypedByRef = 0x16,
	/// System.IntPtr.
	IntPtr = 0x18,
	/// System.UIntPtr.
	UIntPtr = 0x19,
	/// Followed by full method signature.
	FnPointer = 0x1b,
	/// System.Object.
	Object = 0x1c,
	/// Single-dim array with 0 lower bound.
	SzArray = 0x1d,
	/// Generic parameter in a generic method definition, represented as number (compressed unsigned integer).
	MethodGenericParam = 0x1e,
	/// Required modifier : followed by a TypeDef or TypeRef token.
	CModReq = 0x1f,
	/// Optional modifier : followed by a TypeDef or TypeRef token.
	CModOpt = 0x20,
	/// Implemented within the CLI.
	Internal = 0x21,
	/// Or’d with following element types.
	Mod = 0x40,
	/// Sentinel for vararg method signature.
	Sentinel = 0x41,
	/// Denotes a local variable that points at a pinned object.
	Pinned = 0x45,
	/// Indicates an argument of type System.Type.
	Type = 0x50,
	/// Used in custom attributes to specify a boxed object.
	CAttrBoxed = 0x51,
	/// Used in custom attributes to indicate a FIELD.
	CAttrFld = 0x53,
	/// Used in custom attributes to indicate a PROPERTY.
	CAttrProp = 0x54,
	/// Used in custom attributes to specify an enum.
	CAttrEnum = 0x55,
}
