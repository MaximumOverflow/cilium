use std::fmt::Debug;
use std::io::Cursor;
use std::path::Path;

use bumpalo::Bump;

use crate::raw::assembly::Assembly as RawAssembly;
use crate::raw::FromByteStream;
use crate::raw::heaps::{StringHeap as RawStringHeap, BlobHeap as RawBlobHeap};
use crate::raw::heaps::table::{FieldTable, MethodDefTable, StandAloneSigTable, TableHeap, TypeAttributes, TypeDefTable};
use crate::raw::il::{MethodBody as RawMethodBody, OpCodeIterator};
use crate::raw::indices::metadata_token;
use crate::raw::pe::PEFile;
use crate::schema::errors::ReadError;
use crate::schema::heaps::{BlobHeap, StringHeap};
use crate::schema::method::{Method, MethodBody};
use crate::schema::r#type::{Class, DebuggableType, Field, Interface};
use crate::utilities::get_string_from_heap;

#[derive(Debug)]
pub struct Assembly<'l> {
	string_heap: StringHeap<'l>,
	method_defs: Vec<Method<'l>>,
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

		let blobs = raw
			.metadata_root()
			.get_heap::<RawBlobHeap>()
			.ok_or(ReadError::MissingMetadataHeap("#Blob"))?;

		let strings = raw
			.metadata_root()
			.get_heap::<RawStringHeap>()
			.ok_or(ReadError::MissingMetadataHeap("#String"))?;

		let mut blob_heap = BlobHeap::new(bump);
		let mut string_heap = StringHeap::new(bump);

		let types = read_types(ReadTypesDependencies {
			bump,
			tables,
			strings,
			string_heap: &mut string_heap,
		})?;

		let methods = read_methods(ReadMethodsDependencies {
			bump,
			pe_file: raw.pe_file(),
			tables,
			blobs,
			strings,
			blob_heap: &mut blob_heap,
			string_heap: &mut string_heap,
		})?;

		Ok(Self { string_heap, method_defs: methods, type_defs: types })
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

			if def.flags.contains(TypeAttributes::INTERFACE) {
				let name = get_string_from_heap(strings, def.type_name)?;
				let namespace = get_string_from_heap(strings, def.type_namespace)?;

				types.push(bump.alloc(Interface {
					name: string_heap.intern(name),
					namespace: string_heap.intern(namespace),
					metadata_token: metadata_token::TypeDef(i + 1).into(),
					methods: vec![],
				}));

				continue;
			}

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
					fields,
					methods: vec![],
					name: string_heap.intern(name),
					namespace: string_heap.intern(namespace),
					metadata_token: metadata_token::TypeDef(i + 1).into(),
				}));

				continue;
			}
		}
	}
	Ok(types)
}

struct ReadMethodsDependencies<'l, 'r> {
	bump: &'l Bump,
	pe_file: &'r PEFile,
	tables: &'r TableHeap,
	blobs: &'r RawBlobHeap,
	strings: &'r RawStringHeap,
	blob_heap: &'r mut BlobHeap<'l>,
	string_heap: &'r mut StringHeap<'l>,
}

#[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
fn read_methods<'l, 'r>(
	ReadMethodsDependencies {
		pe_file, blobs, strings, string_heap, blob_heap, tables, ..
	}: ReadMethodsDependencies<'l, 'r>,
) -> Result<Vec<Method<'l>>, ReadError> {
	let method_defs = match tables.get_table::<MethodDefTable>() {
		None => return Ok(vec![]),
		Some(fields) => fields.rows(),
	};

	let signatures = match tables.get_table::<StandAloneSigTable>() {
		Some(fields) => fields,
		None => return Err(ReadError::MissingMetadataTable("StandAloneSig")),
	};

	let mut methods = Vec::with_capacity(method_defs.len());
	for (i, def) in method_defs.iter().enumerate() {
		let name = get_string_from_heap(strings, def.name)?;
		let metadata_token = metadata_token::MethodDef(i + 1);
		let mut body = None;

		if def.rva != 0 {
			let Some((_, data, _)) = pe_file.resolve_rva(def.rva) else {
				return Err(ReadError::InvalidMethodRVA(def.rva))
			};

			let mut cursor = Cursor::new(data.as_ref());
			let raw_body = RawMethodBody::read(&mut cursor, blobs, signatures, tables.index_sizes())?;
			if let Some(err) = OpCodeIterator::new(raw_body.code).find_map(|(_, v)| v.err()) {
				return Err(ReadError::InvalidMethodCode(metadata_token.into(), err.into()));
			}

			println!("{}: {:#X?}", name, raw_body);

			body = Some(
				MethodBody {
					max_stack_size: raw_body.max_stack_size,
					init_locals: raw_body.init_locals,
					code: blob_heap.intern(raw_body.code)
				}
			);
		}

		methods.push(Method {
			body,
			metadata_token,
			name: string_heap.intern(name),
		});
	}
	Ok(methods)
}
