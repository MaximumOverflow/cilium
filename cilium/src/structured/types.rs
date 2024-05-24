use std::cell::Cell;
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::io::ErrorKind;

use bumpalo::Bump;
use derivative::Derivative;

use crate::raw::heaps::{BlobHeap, StringHeap};
use crate::raw::heaps::table::{TableHeap, TypeAttributes, TypeDef, Field as FieldRow, FieldAttributes};
use crate::structured::Assembly;
use crate::structured::assembly::AssemblyLoadingError;
use crate::structured::methods::Method;

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub enum Type<'l> {
	Primitive(Primitive),
	Class(&'l Class<'l>),
	Interface(&'l Interface<'l>),
}

impl Display for Type<'_> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		match self {
			Type::Primitive(t) => Display::fmt(t, f),
			Type::Class(t) => Display::fmt(t, f),
			Type::Interface(t) => Display::fmt(t, f),
		}
	}
}

impl Debug for Type<'_> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		match self {
			Type::Primitive(t) => Debug::fmt(t, f),
			Type::Class(t) => Debug::fmt(t, f),
			Type::Interface(t) => Debug::fmt(t, f),
		}
	}
}

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Primitive {
	#[default]
	Void,
	Bool,
	Char,
	Int8,
	UInt8,
	Int16,
	UInt16,
	Int32,
	UInt32,
	Int64,
	UInt64,
	Float,
	Double,
	String,
	IntPtr,
	UIntPtr,
	Object,
}

impl Display for Primitive {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		match self {
			Primitive::Void => write!(f, "void"),
			Primitive::Bool => write!(f, "bool"),
			Primitive::Char => write!(f, "char"),
			Primitive::Int8 => write!(f, "sbyte"),
			Primitive::UInt8 => write!(f, "byte"),
			Primitive::Int16 => write!(f, "short"),
			Primitive::UInt16 => write!(f, "ushort"),
			Primitive::Int32 => write!(f, "int"),
			Primitive::UInt32 => write!(f, "uint"),
			Primitive::Int64 => write!(f, "long"),
			Primitive::UInt64 => write!(f, "ulong"),
			Primitive::Float => write!(f, "float"),
			Primitive::Double => write!(f, "double"),
			Primitive::String => write!(f, "string"),
			Primitive::IntPtr => write!(f, "System.IntPtr"),
			Primitive::UIntPtr => write!(f, "System.UIntPtr"),
			Primitive::Object => write!(f, "object"),
		}
	}
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Class<'l> {
	name: &'l str,
	namespace: &'l str,
	#[derivative(Debug(format_with = "crate::utilities::fmt_debug_cell"))]
	fields: Cell<&'l [Field<'l>]>,
	#[derivative(Debug(format_with = "crate::utilities::fmt_debug_cell"))]
	methods: Cell<&'l [Method]>,
}

impl Display for Class<'_> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		match self.namespace {
			"" => write!(f, "{}", self.name),
			_ => write!(f, "{}.{}", self.namespace, self.name),
		}
	}
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Interface<'l> {
	name: &'l str,
	namespace: &'l str,
	#[derivative(Debug(format_with = "crate::utilities::fmt_debug_cell"))]
	fields: Cell<&'l [Field<'l>]>,
	#[derivative(Debug(format_with = "crate::utilities::fmt_debug_cell"))]
	methods: Cell<&'l [Method]>,
}

impl Display for Interface<'_> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		match self.namespace {
			"" => write!(f, "{}", self.name),
			_ => write!(f, "{}.{}", self.namespace, self.name),
		}
	}
}

#[derive(Derivative, Copy, Clone)]
#[derivative(Debug)]
pub struct Field<'l> {
	name: &'l str,
	flags: FieldAttributes,
	#[derivative(Debug(format_with = "Display::fmt"))]
	ty: Type<'l>,
}

macro_rules! impl_identity {
    ($($ty: ident),*) => {
		$(
			impl Eq for $ty<'_> {}

			impl PartialEq<Self> for $ty<'_> {
				#[inline]
				fn eq(&self, other: &Self) -> bool {
					std::ptr::eq(self, other)
				}
			}

			impl Hash for $ty<'_> {
				fn hash<H: Hasher>(&self, state: &mut H) {
					(self as *const Self).hash(state)
				}
			}
		)*
	};
}

impl_identity!(Class, Interface);

#[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
pub(super) fn load_type_defs<'l>(
	bump: &'l Bump,
	tables: &TableHeap,
	strings: StringHeap,
) -> Result<&'l [Type<'l>], AssemblyLoadingError> {
	let mut types = bumpalo::vec![in bump];

	if let Some(table) = tables.get_table::<TypeDef>() {
		types.reserve(table.len());
		for type_def in table.rows() {
			let type_def = type_def?;
			let name = strings.get(type_def.name).ok_or(ErrorKind::NotFound)?;
			let namespace = strings.get(type_def.namespace).ok_or(ErrorKind::NotFound)?;

			if type_def.flags.contains(TypeAttributes::INTERFACE) {
				types.push(Type::Interface(bump.alloc(Interface {
					name: bump.alloc_str(name),
					namespace: bump.alloc_str(namespace),
					fields: Cell::new(&[]),
					methods: Cell::new(&[]),
				})));
			}
			else if type_def.flags.contains(TypeAttributes::CLASS) {
				types.push(Type::Class(bump.alloc(Class {
					name: bump.alloc_str(name),
					namespace: bump.alloc_str(namespace),
					fields: Cell::new(&[]),
					methods: Cell::new(&[]),
				})));
			}
		}

		assert_eq!(types.len(), table.len());
	}

	Ok(types.into_bump_slice())
}

#[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
pub(super) fn populate_type_defs<'l>(
	bump: &'l Bump,
	blobs: BlobHeap,
	strings: StringHeap,
	tables: &TableHeap,
	assembly: &'l Assembly<'l>,
) -> Result<(), AssemblyLoadingError> {
	let mut fields = bumpalo::vec![in bump];
	if let Some(table) = tables.get_table::<FieldRow>() {
		fields.reserve_exact(fields.len());
		for field in table.rows() {
			let field = field?;
			let name = strings.get(field.name).ok_or(ErrorKind::NotFound)?;
			fields.push(Field {
				name: bump.alloc_str(name),
				flags: field.flags,
				ty: Type::Primitive(Primitive::Void),
			});
		}
	}

	let fields = fields.into_bump_slice();
	if let Some(table) = tables.get_table::<TypeDef>() {
		let mut rows = table.rows();
		if let Some(row) = rows.next() { let _ = row?; }

		let mut start = 0;
		for type_def in assembly.types() {
			let end = match rows.next() {
				None => fields.len(),
				Some(type_def) => type_def?.field_list.idx().unwrap(),
			};
			let range = start..end;
			match type_def {
				Type::Class(class) => {
					class.fields.set(&fields[range]);
				}
				Type::Interface(interface) => {
					interface.fields.set(&fields[range]);
				}
				Type::Primitive(_) => {
					assert_eq!(range.len(), 0);
				}
			}
			start = end;
		}
	}

	Ok(())
}
