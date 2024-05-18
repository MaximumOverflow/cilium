use std::alloc::Layout;
use std::io::{Cursor, Error, ErrorKind, Read};
use std::sync::Arc;
use bitflags::bitflags;

use owning_ref::ArcRef;
use cilium_derive::{FromRepr, Table};

use crate::heaps::{GuidIndex, MetadataHeap, MetadataHeapKind, StringIndex};
use crate::indices::coded_index::{CodedIndexKind, TypeDefOrRef};
use crate::indices::sizes::*;
use crate::utilities::{enumerate_set_bits, FromByteStream, impl_from_byte_stream};

#[derive(Debug)]
pub struct TableHeap {
	major_version: u8,
	minor_version: u8,
}

impl MetadataHeap for TableHeap {
	fn name(&self) -> &str {
		"~#"
	}

	fn data(&self) -> &[u8] {
		&[]
	}

	fn kind(&self) -> MetadataHeapKind {
		MetadataHeapKind::Table
	}
}

impl TryFrom<ArcRef<[u8]>> for TableHeap {
	type Error = Error;
	fn try_from(value: ArcRef<[u8]>) -> Result<Self, Self::Error> {
		#[repr(C)]
		#[derive(Copy, Clone)]
		struct Header {
			reserved_0: u32,
			major_version: u8,
			minor_version: u8,
			heap_sizes: u8,
			reserved_1: u8,
			valid: u64,
			sorted: u64,
		}

		impl_from_byte_stream!(Header);

		let mut stream = Cursor::new(value.as_ref());
		let Header { heap_sizes, valid, .. } = Header::read(&mut stream, &())?;

		let table_count = valid.count_ones() as usize;
		let mut table_sizes = vec![0u32; 64];

		for i in enumerate_set_bits(valid) {
			let mut bytes = 0u32.to_ne_bytes();
			stream.read_exact(&mut bytes)?;
			table_sizes[i] = u32::from_le_bytes(bytes);
		}

		let idx_sizes = IndexSizes::new(heap_sizes, table_sizes.as_slice().try_into().unwrap());

		let mut tables: Vec<Arc<dyn Table>> = Vec::with_capacity(table_count);
		for (i, bit) in enumerate_set_bits(valid).enumerate() {
			let len = table_sizes[bit] as usize;
			let Some(kind) = TableKind::from_repr(bit) else {
				return Err(ErrorKind::InvalidData.into());
			};

			tables.push(match kind {
				TableKind::Module => Arc::new(ModuleTable::read(&mut stream, &idx_sizes, len)?),
				TableKind::TypeDef => Arc::new(TypeDefTable::read(&mut stream, &idx_sizes, len)?),
				_ => unimplemented!("Unimplemented table {:?}", kind),
			})
		}

		unimplemented!()
	}
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, FromRepr)]
pub enum TableKind {
	Module = 0x00,
	TypeRef = 0x01,
	TypeDef = 0x02,
	FieldPtr = 0x03,
	Field = 0x04,
	MethodPtr = 0x05,
	Method = 0x06,
	ParamPtr = 0x07,
	Param = 0x08,
	InterfaceImpl = 0x09,
	MemberRef = 0x0a,
	Constant = 0x0b,
	CustomAttribute = 0x0c,
	FieldMarshal = 0x0d,
	DeclSecurity = 0x0e,
	ClassLayout = 0x0f,
	FieldLayout = 0x10,
	StandAloneSig = 0x11,
	EventMap = 0x12,
	EventPtr = 0x13,
	Event = 0x14,
	PropertyMap = 0x15,
	PropertyPtr = 0x16,
	Property = 0x17,
	MethodSemantics = 0x18,
	MethodImpl = 0x19,
	ModuleRef = 0x1a,
	TypeSpec = 0x1b,
	ImplMap = 0x1c,
	FieldRVA = 0x1d,
	EncLog = 0x1e,
	EncMap = 0x1f,
	Assembly = 0x20,
	AssemblyProcessor = 0x21,
	AssemblyOS = 0x22,
	AssemblyRef = 0x23,
	AssemblyRefProcessor = 0x24,
	AssemblyRefOS = 0x25,
	File = 0x26,
	ExportedType = 0x27,
	ManifestResource = 0x28,
	NestedClass = 0x29,
	GenericParam = 0x2a,
	MethodSpec = 0x2b,
	GenericParamConstraint = 0x2c,

	Document = 0x30,
	MethodDebugInformation = 0x31,
	LocalScope = 0x32,
	LocalVariable = 0x33,
	LocalConstant = 0x34,
	ImportScope = 0x35,
	StateMachineMethod = 0x36,
	CustomDebugInformation = 0x37,
}

pub trait Table {
	fn len(&self) -> usize;
	fn kind(&self) -> TableKind;
}

#[derive(Debug, Clone, Table)]
pub struct Module {
	generation: u16,
	name: StringIndex,
	mv_id: GuidIndex,
	enc_id: GuidIndex,
	enc_base_id: GuidIndex,
}

bitflags! {
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct TypeAttributes: u32 {
		// #### Visibility attributes ####
		/// Use this mask to retrieve visibility information.
		const VISIBILITY_MASK = 0x00000007;
		/// Class has no public scope.
		const NOT_PUBLIC = 0x00000000;
		/// Class has public scope.
		const PUBLIC = 0x00000001;
		/// Class is nested with public visibility.
		const NESTED_PUBLIC = 0x00000002;
		/// Class is nested with private visibility.
		const NESTED_PRIVATE = 0x00000003;
		/// Class is nested with family visibility.
		const NESTED_FAMILY = 0x00000004;
		/// Class is nested with assembly visibility.
		const NESTED_ASSEMBLY = 0x00000005;
		/// Class is nested with family and assembly.
		const NESTED_FAMILY_AND_ASSEMBLY = 0x00000006;
		/// Class is nested with family or assembly.
		const NESTED_FAMILY_OR_ASSEMBLY = 0x00000007;

		// #### Class layout attributes ####
		/// Use this mask to retrieve class layout information.
		const LAYOUT_MASK = 0x00000018;
		/// Class fields are auto-laid out.
		const AUTO_LAYOUT = 0x00000000;
		/// Class fields are laid out sequentially.
		const SEQUENTIAL_LAYOUT = 0x00000008;
		/// Layout is supplied explicitly.
		const EXPLICIT_LAYOUT = 0x00000010;

		// #### Class semantics attributes ####
		/// Use this mask to retrive class semantics information.
		const CLASS_SEMANTICS_MASK = 0x00000020;
		/// Type is a class.
		const CLASS = 0x00000000;
		/// Type is an interface.
		const INTERFACE = 0x00000020;

		// #### Special semantics in addition to class semantics ####
		/// Class is abstract.
		const ABSTRACT =  0x00000080;
		/// Class cannot be extended.
		const SEALED =  0x00000100;
		/// Class name is special.
		const SPECIAL_NAME =  0x00000400;

		// #### Implementation Attributes ####
		/// Class/Interface is imported.
		const IMPORTED = 0x00001000;
		/// Class/Interface is imported.
		const SERIALIZABLE = 0x00002000;

		// #### String formatting Attributes ####
		/// Use this mask to retrieve string information for native interop.
		const STRING_FORMAT_MASK = 0x00030000;
		/// LPSTR is interpreted as ANSI.
		const ANSI_CLASS =  0x00000000;
		/// LPSTR is interpreted as Unicode
		const UNICODE_CLASS =  0x00010000;
		/// LPSTR is interpreted automatically.
		const AUTO_CLASS =  0x00020000;
		/// A non-standard encoding specified by CUSTOM_STRING_FORMAT_MASK.
		const CUSTOM_FORMAT_CLASS = 0x00030000;
		/// Use this mask to retrieve non-standard encoding information for native interop. The meaning of the values of these 2 bits is unspecified.
		const CUSTOM_STRING_FORMAT_MASK = 0x00C00000;

		// #### Class Initialization Attributes ####
		/// Initialize the class before first static field access.
		const BeforeFieldInit = 0x00100000;

		// #### Additional Flags ####
		/// CLI provides 'special' behavior, depending upon the name of the Type.
		const RTSpecialName = 0x00000800;
		/// Type has security associate with it.
		const HasSecurity = 0x00040000;
		/// This ExportedType entry is a type forwarder.
		const IsTypeForwarder = 0x00200000;
	}
}

impl_from_byte_stream!(TypeAttributes);

#[derive(Debug, Clone, Table)]
pub struct TypeDef {
	flags: TypeAttributes,
	type_name: StringIndex,
	type_namespace: StringIndex,
	extends: TypeDefOrRef,
	field_list: FieldIndex,
	method_list: MethodIndex,
}

#[derive(Debug, Clone, Table)]
pub struct Field {
	// TODO
}

#[derive(Debug, Clone, Table)]
pub struct Method {
	// TODO
}
