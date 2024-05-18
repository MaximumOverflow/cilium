use std::io::{Cursor, Error, Read};
use std::sync::Arc;
use bitflags::bitflags;

use owning_ref::ArcRef;
use cilium_derive::Table;

use crate::heaps::{MetadataHeap, MetadataHeapKind, StringIndex};
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
		let Header { heap_sizes, valid, sorted, .. } = Header::read(&mut stream)?;

		let table_count = valid.count_ones() as usize;
		let mut table_sizes = [0u32; 64];

		unsafe {
			stream.read_exact(std::slice::from_raw_parts_mut(table_sizes.as_mut_ptr() as *mut u8, 4 * table_count))?;
		}

		#[cfg(target_endian = "big")]
		for i in 0..table_count {
			table_sizes[i] = table_sizes[i].to_be();
		}

		let mut tables: Vec<Arc<dyn Table>> = Vec::with_capacity(table_count);
		for (i, bit) in enumerate_set_bits(valid).enumerate() {
			let len = table_sizes[i] as usize;
			tables.push(match bit {
				0x00 => Arc::new(ModuleTable::read(&mut stream, heap_sizes, len)?),
				_ => unimplemented!("Unimplemented table {:#X?}", bit),
			})
		}

		unimplemented!()
	}
}

pub trait Table {
	fn len(&self) -> usize;
	fn row_size(&self) -> usize;
}

#[derive(Debug, Table)]
pub struct Module {
	generation: u16,
	name: StringIndex,
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
