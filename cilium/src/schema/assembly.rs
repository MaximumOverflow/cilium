use std::cell::Cell;
use std::fmt::Debug;
use std::io::Cursor;
use std::path::Path;

use bumpalo::Bump;
use derivative::Derivative;

use crate::raw::assembly::Assembly as RawAssembly;
use crate::raw::FromByteStream;
use crate::raw::heaps::{BlobHeap as RawBlobHeap, StringHeap as RawStringHeap};
use crate::raw::heaps::table::{FieldTable, MethodDefTable, StandAloneSigTable, TableHeap, TypeAttributes, TypeDefTable};
use crate::raw::il::{MethodBody as RawMethodBody, OpCodeIterator, TypeSignature, TypeSignatureTag};
use crate::raw::indices::metadata_token;
use crate::raw::pe::PEFile;
use crate::schema::errors::ReadError;
use crate::schema::heaps::{BlobHeap, DataPool, StringHeap};
use crate::schema::method::{Method, MethodBody};
use crate::schema::r#type::{GenericTypeInstantiationError, PrimitiveType, Type, TypeData, TypeKind, TypePool};
use crate::utilities::get_string_from_heap;

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Assembly<'l> {
	#[derivative(Debug="ignore")]
	data_pool: &'l DataPool<'l>,
	string_heap: StringHeap<'l>,
	method_defs: Vec<Method<'l>>,
	type_defs: &'l [&'l Type<'l>],
}

impl<'l> Assembly<'l> {
	#[cfg(feature = "memmap2")]
	pub fn from_path(pool: &'l DataPool<'l>, path: impl AsRef<Path>) -> Result<Self, ReadError> {
		let file = std::fs::File::open(path)?;
		let bytes = unsafe { memmap2::Mmap::map(&file) }?;
		Self::from_bytes(pool, bytes.as_ref())
	}

	#[cfg(not(feature = "memmap2"))]
	pub fn from_path(pool: &'l DataPool<'l>, path: impl AsRef<Path>) -> Result<Self, ReadError> {
		let bytes = std::fs::read(path)?;
		Self::from_bytes(pool, bytes.as_slice())
	}

	#[inline]
	pub fn from_bytes(pool: &'l DataPool<'l>, bytes: &[u8]) -> Result<Self, ReadError> {
		let mut cursor = Cursor::new(bytes);
		let pe = PEFile::read(&mut cursor, &())?;
		let raw = RawAssembly::try_from(pe)?;
		Self::from_raw_assembly(pool, &raw)
	}

	#[inline(never)]
	#[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
	pub fn from_raw_assembly(data_pool: &'l DataPool<'l>, raw: &RawAssembly) -> Result<Self, ReadError> {
		let bump = data_pool.bump();

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
			pool: data_pool,
			tables,
			strings,
			string_heap: &mut string_heap,
		})?;

		let methods = read_methods(ReadMethodsDependencies {
			pool: data_pool,
			pe_file: raw.pe_file(),
			tables,
			blobs,
			strings,
			blob_heap: &mut blob_heap,
			string_heap: &mut string_heap,
			types,
		})?;

		Ok(Self { data_pool, string_heap, method_defs: methods, type_defs: types })
	}
}

struct ReadTypesDependencies<'l, 'r> {
	pool: &'l DataPool<'l>,
	tables: &'r TableHeap,
	strings: &'r RawStringHeap,
	string_heap: &'r mut StringHeap<'l>,
}

#[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
fn read_types<'l, 'r>(
	ReadTypesDependencies {
  		pool, tables, strings, string_heap
	}: ReadTypesDependencies<'l, 'r>
) -> Result<&'l [&'l Type<'l>], ReadError> {
	let Some(type_defs) = tables.get_table::<TypeDefTable>() else {
		return Ok(&[]);
	};

	// let fields = match tables.get_table::<FieldTable>() {
	// 	Some(fields) => fields.rows(),
	// 	None if type_defs.iter().all(|t| t.field_list.idx().is_none()) => &[], // Not so sure about this but we'll see
	// 	None => return Err(ReadError::MissingMetadataTable("Field")),
	// };

	let type_defs = type_defs.rows();
	let types = pool.types().declare_types(type_defs, strings, string_heap)?;

	for i in 0..types.len() {
		let def = &type_defs[i];
		let ty = &mut types[i];

		// let raw_fields = match def.field_list.idx() {
		// 	None => &[],
		// 	Some(idx) => {
		// 		let end = match type_defs.get(i + 1) {
		// 			None => fields.len(),
		// 			Some(def) => def.field_list.idx().unwrap(), // Not so sure about this either but we'll see
		// 		};
		// 		&fields[idx..end]
		// 	}
		// };

		match ty.kind {
			TypeKind::Class => {
				ty.data.set(TypeData::Init {
					metadata_token: metadata_token::TypeDef(i + 1).into(),
					name: ty.name(),
					namespace: ty.namespace(),
					fields: &[],
					methods: &[],
					is_value_type: false,
					element_type: None,
				});
			}
			TypeKind::Interface => {
				ty.data.set(TypeData::Init {
					metadata_token: metadata_token::TypeDef(i + 1).into(),
					name: ty.name(),
					namespace: ty.namespace(),
					fields: &[],
					methods: &[],
					is_value_type: false,
					element_type: None,
				});
			}
			_ => unreachable!(),
		}
	}

	// This is fine, it's just the typesystem being iffy
	unsafe { Ok(std::mem::transmute(types)) }
}

struct ReadMethodsDependencies<'l, 'r> {
	pool: &'l DataPool<'l>,
	pe_file: &'r PEFile,
	tables: &'r TableHeap,
	blobs: &'r RawBlobHeap,
	strings: &'r RawStringHeap,
	blob_heap: &'r mut BlobHeap<'l>,
	string_heap: &'r mut StringHeap<'l>,
	types: &'l [&'l Type<'l>]
}

#[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
fn read_methods<'l, 'r>(
	ReadMethodsDependencies {
		pool, pe_file, blobs, strings, string_heap, blob_heap, tables, types, ..
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

			let locals = pool.bump().alloc_slice_fill_copy(
				raw_body.locals.len(),
				pool.types().get_primitive(PrimitiveType::Void)
			);
			for (i, local_sig) in raw_body.locals.iter().enumerate() {
				locals[i] = resolve_type_signature(local_sig, types, pool.types())?;
			}

			body = Some(
				MethodBody {
					max_stack_size: raw_body.max_stack_size,
					init_locals: raw_body.init_locals,
					code: blob_heap.intern(raw_body.code),
					locals,
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

fn resolve_type_signature<'l>(
	sig: &TypeSignature,
	type_defs: &[&'l Type<'l>],
	pool: &'l TypePool<'l>,
) -> Result<&'l Type<'l>, ReadError> {
	resolve_type_signature_tag(&sig.as_tags_tree(), type_defs, pool)
}

fn resolve_type_signature_tag<'l>(
	sig: &TypeSignatureTag,
	type_defs: &[&'l Type<'l>],
	pool: &'l TypePool<'l>,
) -> Result<&'l Type<'l>, ReadError> {
	match sig {
		TypeSignatureTag::Void => Ok(pool.get_primitive(PrimitiveType::Void)),
		TypeSignatureTag::Char => Ok(pool.get_primitive(PrimitiveType::Char)),
		TypeSignatureTag::Bool => Ok(pool.get_primitive(PrimitiveType::Boolean)),
		TypeSignatureTag::Int1 => Ok(pool.get_primitive(PrimitiveType::Int8)),
		TypeSignatureTag::Int2 => Ok(pool.get_primitive(PrimitiveType::Int16)),
		TypeSignatureTag::Int4 => Ok(pool.get_primitive(PrimitiveType::Int32)),
		TypeSignatureTag::Int8 => Ok(pool.get_primitive(PrimitiveType::Int64)),
		TypeSignatureTag::UInt1 => Ok(pool.get_primitive(PrimitiveType::UInt8)),
		TypeSignatureTag::UInt2 => Ok(pool.get_primitive(PrimitiveType::UInt16)),
		TypeSignatureTag::UInt4 => Ok(pool.get_primitive(PrimitiveType::UInt32)),
		TypeSignatureTag::UInt8 => Ok(pool.get_primitive(PrimitiveType::UInt64)),
		TypeSignatureTag::Float => Ok(pool.get_primitive(PrimitiveType::Float)),
		TypeSignatureTag::Double => Ok(pool.get_primitive(PrimitiveType::Double)),
		TypeSignatureTag::String => Ok(pool.get_primitive(PrimitiveType::String)),
		TypeSignatureTag::IntPtr => Ok(pool.get_primitive(PrimitiveType::IntPtr)),
		TypeSignatureTag::UIntPtr => Ok(pool.get_primitive(PrimitiveType::UIntPtr)),
		TypeSignatureTag::Object => Ok(pool.get_primitive(PrimitiveType::Object)),
		TypeSignatureTag::TypedByRef => Ok(pool.get_primitive(PrimitiveType::TypedByRef)),

		TypeSignatureTag::Pointer(base) => {
			let base = resolve_type_signature(base, type_defs, pool)?;
			Ok(pool.get_pointer(base))
		},
		TypeSignatureTag::Reference(base) => {
			let base = resolve_type_signature(base, type_defs, pool)?;
			Ok(pool.get_reference(base))
		},

		TypeSignatureTag::ValueType(token) | TypeSignatureTag::ClassType(token) => {
			if let Ok(type_def) = TryInto::<metadata_token::TypeDef>::try_into(*token) {
				return match type_def.0 {
					0 => Err(ReadError::InvalidTypeSignature),
					_ => type_defs
						.get(type_def.0)
						.cloned()
						.ok_or(ReadError::InvalidTypeSignature),
				}
			}
			if let Ok(type_ref) = TryInto::<metadata_token::TypeRef>::try_into(*token) {
				unimplemented!()
			}
			unreachable!()
		},

		TypeSignatureTag::GenericInst(inst) => unsafe {
			// IDK what the hell is happening here, wonky borrow checker.
			let ty: &Type = std::mem::transmute(resolve_type_signature(inst.ty(), type_defs, pool)?);
			let mut params = Vec::with_capacity(inst.params_count());
			for sig in inst.params() {
				let ty = resolve_type_signature_tag(&sig, type_defs, pool)?;
				params.push(ty);
			}
			if !matches!(ty.kind, TypeKind::Class | TypeKind::Interface) {
				return Err(ReadError::InvalidTypeSignature);
			}
			match pool.get_generic_instantiation(ty, &params) {
				Ok(ty) => Ok(ty),
				Err(err) => match err {
					GenericTypeInstantiationError::TypeIsNotLoaded => Err(ReadError::InvalidTypeSignature),
					GenericTypeInstantiationError::TypeIsNotGeneric => Err(ReadError::InvalidTypeSignature),
					GenericTypeInstantiationError::InvalidGenericParameterCount => Err(ReadError::InvalidTypeSignature),
				}
			}
		},

		// TODO Make function pointer
		TypeSignatureTag::FnPointer(_) => {
			Ok(pool.get_primitive(PrimitiveType::Unimplemented))
		}

		// TODO Return variable signature flags
		TypeSignatureTag::SzArray(sig) => {
			let ty = resolve_type_signature(sig, type_defs, pool)?;
			Ok(pool.get_array(ty))
		},

		TypeSignatureTag::GenericParam(idx) => {
			// TODO Validate index
			Ok(pool.get_generic_type_param(*idx))
		}

		TypeSignatureTag::MethodGenericParam(idx) => {
			// TODO Validate index
			Ok(pool.get_generic_method_param(*idx))
		}

		// TODO Return variable signature flags
		TypeSignatureTag::Pinned(sig) => {
			resolve_type_signature(sig, type_defs, pool)
		},

		_ => unimplemented!("Unimplemented TypeSignatureTag {sig:#X?}"),
	}
}
