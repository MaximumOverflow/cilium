use std::fmt::Debug;
use std::io::Cursor;
use std::path::Path;

use bumpalo::Bump;

use crate::raw::assembly::Assembly as RawAssembly;
use crate::raw::FromByteStream;
use crate::raw::heaps::{StringHeap as RawStringHeap};
use crate::raw::heaps::table::{FieldTable, TableHeap, TypeAttributes, TypeDefTable};
use crate::raw::indices::metadata_token::TypeDef;
use crate::raw::pe::PEFile;
use crate::schema::errors::ReadError;
use crate::schema::heaps::StringHeap;
use crate::schema::r#type::{Class, DebuggableType, Field};
use crate::utilities::get_string_from_heap;

#[derive(Debug)]
pub struct Assembly<'l> {
	string_heap: StringHeap<'l>,
	type_defs: Vec<&'l dyn DebuggableType<'l>>,
}

impl<'l> Assembly<'l> {
	#[cfg(feature = "memmap2")]
	pub fn from_path(bump: &'l Bump, path: impl AsRef<Path>) -> Result<Self, ReadError> {
		let file = std::fs::File::open(path)?;
		let bytes = unsafe { memmap2::Mmap::map(&file) }?;
		Self::from_bytes(bump, bytes.as_ref())
	}

	#[cfg(not(feature = "memmap2"))]
	pub fn from_path(bump: &'l Bump, path: impl AsRef<Path>) -> Result<Self, ReadError> {
		let bytes = std::fs::read(path)?;
		Self::from_bytes(bump, bytes.as_slice())
	}

	#[inline]
	pub fn from_bytes(bump: &'l Bump, bytes: &[u8]) -> Result<Self, ReadError> {
		let mut cursor = Cursor::new(bytes);
		let pe = PEFile::read(&mut cursor, &())?;
		let raw = RawAssembly::try_from(pe)?;
		Self::from_raw_assembly(bump, &raw)
	}

	#[inline(never)]
	#[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
	pub fn from_raw_assembly(bump: &'l Bump, raw: &RawAssembly) -> Result<Self, ReadError> {
		let tables = raw
			.metadata_root()
			.get_heap::<TableHeap>()
			.ok_or(ReadError::MissingMetadataHeap("#~"))?;

		let strings = raw
			.metadata_root()
			.get_heap::<RawStringHeap>()
			.ok_or(ReadError::MissingMetadataHeap("#String"))?;

		let mut string_heap = StringHeap::new(bump);
		let types = read_types(ReadTypesDependencies {
			bump,
			tables,
			strings,
			string_heap: &mut string_heap,
		})?;

		Ok(Self { string_heap, type_defs: types })
	}
}

struct ReadTypesDependencies<'l, 'r> {
	bump: &'l Bump,
	tables: &'r TableHeap,
	strings: &'r RawStringHeap,
	string_heap: &'r mut StringHeap<'l>,
}

#[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
fn read_types<'l, 'r>(
	ReadTypesDependencies {
  		bump, tables, strings, string_heap
	}: ReadTypesDependencies<'l, 'r>
) -> Result<Vec<&'l dyn DebuggableType<'l>>, ReadError> {

	let mut types: Vec<&'l dyn DebuggableType<'l>> = vec![];

	if let Some(type_defs) = tables.get_table::<TypeDefTable>() {
		let type_defs = type_defs.rows();
		let fields = match tables.get_table::<FieldTable>() {
			Some(fields) => fields.rows(),
			None if type_defs.iter().all(|t| t.field_list.idx().is_none()) => &[], // Not so sure about this but we'll see
			None => return Err(ReadError::MissingMetadataTable("Field")),
		};

		types.reserve(type_defs.len());
		for (i, def) in type_defs.iter().enumerate() {
			let raw_fields = match def.field_list.idx() {
				None => &[],
				Some(idx) => {
					let end = match type_defs.get(i + 1) {
						None => fields.len(),
						Some(def) => def.field_list.idx().unwrap(), // Not so sure about this either but we'll see
					};
					&fields[idx..end]
				}
			};

			if def.flags.contains(TypeAttributes::CLASS) {
				let name = get_string_from_heap(strings, def.type_name)?;
				let namespace = get_string_from_heap(strings, def.type_namespace)?;

				let mut fields = Vec::with_capacity(raw_fields.len());
				for field in raw_fields {
					let name = get_string_from_heap(strings, field.name)?;
					fields.push(Field {
						name: string_heap.intern(name),
					});
				}

				types.push(bump.alloc(Class {
					name: string_heap.intern(name),
					namespace: string_heap.intern(namespace),
					fields,
					metadata_token: TypeDef(i).into(),
				}));
				continue;
			}

			if def.flags.contains(TypeAttributes::INTERFACE) {

			}
		}
	}
	Ok(types)
}
