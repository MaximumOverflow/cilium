use std::alloc::Layout;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::io::Write;

use bumpalo::Bump;
use derivative::Derivative;
use nohash_hasher::BuildNoHashHasher;

use crate::raw::heaps::table;
use crate::raw::heaps::table::TypeAttributes;
use crate::raw::indices::{metadata_token, metadata_token::MetadataToken};
use crate::schema::heaps::StringHeap;
use crate::schema::method::Method;
use crate::schema::ReadError;
use crate::utilities::get_string_from_heap;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum TypeKind {
	Class,
	Array,
	Pointer,
	Reference,
	Interface,
	Primitive,
	GenericParameter,
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Type<'l> {
	#[derivative(Debug="ignore")]
	pub(crate) type_pool: &'l TypePool<'l>,
	pub(crate) kind: TypeKind,
	pub(crate) data: Cell<TypeData<'l>>,
}

#[derive(Debug, Copy, Clone)]
pub(super) enum TypeData<'l> {
	Uninit {
		name: &'l str,
		namespace: &'l str,
	},
	Init {
		metadata_token: MetadataToken,
		name: &'l str,
		namespace: &'l str,
		fields: &'l [Field<'l>],
		methods: &'l [Method<'l>],
		is_value_type: bool,
		element_type: Option<&'l Type<'l>>,
	},
	TypeGeneric(u32),
	MethodGeneric(u32),
}

impl<'l> Type<'l> {
	pub fn name(&self) -> &'l str {
		match self.data.get() {
			TypeData::Init { name, .. } => name,
			TypeData::Uninit { name, .. } => name,
			_ => ""
		}
	}

	pub fn namespace(&self) -> &'l str {
		match self.data.get() {
			TypeData::Init { namespace, .. } => namespace,
			TypeData::Uninit { namespace, .. } => namespace,
			_ => ""
		}
	}

	pub fn write_as_blob(&self, stream: &mut dyn Write) -> std::io::Result<()> {
		match self.data.get() {
			TypeData::Uninit { .. } => {
				let err = format!("Type `{self}` is not initialized");
				return Err(std::io::Error::new(std::io::ErrorKind::NotFound, err));
			}
			TypeData::Init {
				metadata_token,
				element_type ,
				name, namespace,
				..
			} => match self.kind {
				TypeKind::Class | TypeKind::Interface => {
					let mut buffer = [0u8; 5];
					buffer[0] = 0x15;
					buffer[1..5].copy_from_slice(&metadata_token.raw().to_le_bytes());
					stream.write_all(&buffer)
				},
				TypeKind::Array => {
					stream.write_all(&[0x1D])?;
					element_type.unwrap().write_as_blob(stream)
				},
				TypeKind::Pointer => {
					stream.write_all(&[0x0F])?;
					element_type.unwrap().write_as_blob(stream)
				},
				TypeKind::Reference => {
					stream.write_all(&[0x10])?;
					element_type.unwrap().write_as_blob(stream)
				},
				TypeKind::Primitive => {
					let byte = match (namespace, name) {
						("System", "Void") => 0x01,
						("System", "Char") => 0x03,
						("System", "Int8") => 0x04,
						("System", "Int16") => 0x06,
						("System", "Int32") => 0x08,
						("System", "Int64") => 0x0A,
						("System", "UInt8") => 0x05,
						("System", "UInt16") => 0x07,
						("System", "UInt32") => 0x09,
						("System", "Boolean") => 0x02,
						("System", "UInt64") => 0x0B,
						("System", "Float") => 0x0C,
						("System", "Double") => 0x0D,
						("System", "String") => 0x0E,
						("System", "IntPtr") => 0x18,
						("System", "UIntPtr") => 0x19,
						_ => unreachable!(),
					};
					stream.write_all(&[byte])
				}
				TypeKind::GenericParameter => unreachable!(),
			}
			TypeData::TypeGeneric(idx) => {
				unimplemented!()
			}
			TypeData::MethodGeneric(idx) => {
				unimplemented!()
			}
		}
	}
}

impl Display for Type<'_> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		let (name, namespace) = (self.name(), self.namespace());
		match namespace.is_empty() {
			true => write!(f, "{}", name),
			false => write!(f, "{}.{}", namespace, name),
		}
	}
}

impl Eq for Type<'_> {}

impl PartialEq<Self> for Type<'_> {
	fn eq(&self, other: &Self) -> bool {
		std::ptr::eq(self, other)
	}
}

impl Hash for Type<'_> {
	fn hash<H: Hasher>(&self, state: &mut H) {
		(self as *const Type).hash(state)
	}
}

#[derive(Debug)]
pub struct Field<'l> {
	pub(crate) name: &'l str,
}

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Hash)]
pub enum PrimitiveType {
	#[default]
	Void,
	Boolean,
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
	TypedByRef,
	// TODO Temporary
	Unimplemented,
}

pub struct TypePool<'l> {
	bump: &'l Bump,
	primitives: RefCell<HashMap<PrimitiveType, &'l Type<'l>, BuildNoHashHasher<usize>>>,
	pointers: RefCell<HashMap<*const Type<'l>, &'l Type<'l>, BuildNoHashHasher<usize>>>,
	references: RefCell<HashMap<*const Type<'l>, &'l Type<'l>, BuildNoHashHasher<usize>>>,
	generic_type_params: RefCell<HashMap<u32, &'l Type<'l>, BuildNoHashHasher<u32>>>,
	generic_method_params: RefCell<HashMap<u32, &'l Type<'l>, BuildNoHashHasher<u32>>>,
	generic_instantiations: RefCell<HashMap<(&'l Type<'l>, &'l [&'l Type<'l>]), &'l Type<'l>, BuildNoHashHasher<usize>>>,
}

impl<'l> TypePool<'l> {
	pub(crate) fn new(bump: &'l Bump) -> Self {
		Self {
			bump,
			pointers: Default::default(),
			references: Default::default(),
			primitives: Default::default(),
			generic_type_params: Default::default(),
			generic_method_params: Default::default(),
			generic_instantiations: Default::default(),
		}
	}

	pub fn get_primitive(&'l self, ty: PrimitiveType) -> &'l Type<'l> {
		let mut primitives = self.primitives.borrow_mut();
		if let Some(ty) = primitives.get(&ty) {
			return ty;
		}
		primitives.entry(ty).or_insert_with(|| self.bump.alloc(Type {
			type_pool: self,
			kind: match ty {
				PrimitiveType::TypedByRef => TypeKind::Class,
				_ => TypeKind::Primitive,
			},
			data: Cell::new(TypeData::Uninit {
				namespace: "System",
				name: match ty {
					PrimitiveType::Void => "Void",
					PrimitiveType::Boolean => "Boolean",
					PrimitiveType::Char => "Char",
					PrimitiveType::Int8 => "Int8",
					PrimitiveType::UInt8 => "UInt8",
					PrimitiveType::Int16 => "Int16",
					PrimitiveType::UInt16 => "UInt16",
					PrimitiveType::Int32 => "Int32",
					PrimitiveType::UInt32 => "UInt32",
					PrimitiveType::Int64 => "Int64",
					PrimitiveType::UInt64 => "UInt64",
					PrimitiveType::Float => "Float",
					PrimitiveType::Double => "Double",
					PrimitiveType::String => "String",
					PrimitiveType::IntPtr => "IntPtr",
					PrimitiveType::UIntPtr => "UIntPtr",
					PrimitiveType::Object => "Object",
					PrimitiveType::TypedByRef => "TypedByRef",
					PrimitiveType::Unimplemented => "<Unimplemented>",
				},
			}),
		}))
	}

	pub fn get_pointer(&'l self, ty: &'l Type<'l>) -> &'l Type<'l> {
		let mut pointers = self.pointers.borrow_mut();
		pointers.entry(ty as _).or_insert_with(|| self.bump.alloc(Type {
			type_pool: self,
			kind: TypeKind::Pointer,
			data: Cell::new(TypeData::Init {
				metadata_token: metadata_token::TypeDef(0).into(),
				name: unsafe {
					let name = ty.name();
					let len = name.len() + 1;
					let ptr = self.bump.alloc_layout(Layout::array::<u8>(len).unwrap());
					let slice = std::slice::from_raw_parts_mut(ptr.as_ptr(), len);
					slice[..name.len()].copy_from_slice(name.as_bytes());
					slice[name.len()] = b'*';
					std::str::from_utf8_unchecked(slice)
				},
				namespace: ty.namespace(),
				fields: &[],
				methods: &[],
				is_value_type: true,
				element_type: Some(ty),
			})
		}))
	}

	pub fn get_reference(&'l self, ty: &'l Type<'l>) -> &'l Type<'l> {
		let mut pointers = self.pointers.borrow_mut();
		pointers.entry(ty as _).or_insert_with(|| self.bump.alloc(Type {
			type_pool: self,
			kind: TypeKind::Reference,
			data: Cell::new(TypeData::Init {
				metadata_token: metadata_token::TypeDef(0).into(),
				name: unsafe {
					let name = ty.name();
					let len = name.len() + 1;
					let ptr = self.bump.alloc_layout(Layout::array::<u8>(len).unwrap());
					let slice = std::slice::from_raw_parts_mut(ptr.as_ptr(), len);
					slice[..name.len()].copy_from_slice(name.as_bytes());
					slice[name.len()] = b'&';
					std::str::from_utf8_unchecked(slice)
				},
				namespace: ty.namespace(),
				fields: &[],
				methods: &[],
				is_value_type: true,
				element_type: Some(ty),
			})
		}))
	}

	pub fn get_array(&'l self, ty: &'l Type<'l>) -> &'l Type<'l> {
		let mut pointers = self.pointers.borrow_mut();
		pointers.entry(ty as _).or_insert_with(|| self.bump.alloc(Type {
			type_pool: self,
			kind: TypeKind::Array,
			data: Cell::new(TypeData::Init {
				metadata_token: metadata_token::TypeDef(0).into(),
				name: unsafe {
					let name = ty.name();
					let len = name.len() + 2;
					let ptr = self.bump.alloc_layout(Layout::array::<u8>(len).unwrap());
					let slice = std::slice::from_raw_parts_mut(ptr.as_ptr(), len);
					slice[..name.len()].copy_from_slice(name.as_bytes());
					slice[name.len()] = b'[';
					slice[name.len() + 1] = b']';
					std::str::from_utf8_unchecked(slice)
				},
				namespace: ty.namespace(),
				fields: &[],
				methods: &[],
				is_value_type: true,
				element_type: Some(ty),
			})
		}))
	}

	pub fn get_generic_instantiation(
		&'l self,
		ty: &'l Type<'l>,
		params: &[&'l Type<'l>],
	) -> Result<&'l Type<'l>, GenericTypeInstantiationError> {
		let TypeData::Init { .. } = ty.data.get() else {
			return Err(GenericTypeInstantiationError::TypeIsNotLoaded);
		};

		// TODO Make instantiation
		Ok(ty)
	}

	pub(crate) fn get_generic_type_param(&'l self, idx: u32) -> &'l Type<'l> {
		let mut params = self.generic_type_params.borrow_mut();
		params.entry(idx).or_insert_with(|| self.bump.alloc(Type {
			type_pool: self,
			kind: TypeKind::GenericParameter,
			data: Cell::new(TypeData::TypeGeneric(idx)),
		}))
	}

	pub(crate) fn get_generic_method_param(&'l self, idx: u32) -> &'l Type<'l> {
		let mut params = self.generic_method_params.borrow_mut();
		params.entry(idx).or_insert_with(|| self.bump.alloc(Type {
			type_pool: self,
			kind: TypeKind::GenericParameter,
			data: Cell::new(TypeData::MethodGeneric(idx)),
		}))
	}

	pub(crate) fn declare_types(
		&'l self,
		decls: &[table::TypeDef],
		strings: &crate::raw::heaps::StringHeap,
		string_heap: &mut StringHeap<'l>,
	) -> Result<&'l mut [&'l mut Type<'l>], ReadError> {
		let types = self.bump.alloc_slice_fill_with(decls.len(), |_| self.bump.alloc(Type {
			type_pool: self,
			kind: TypeKind::Class,
			data: Cell::new(TypeData::Uninit { name: "", namespace: "" }),
		}));

		for i in 0..types.len() {
			let def = &decls[i];
			let ty = &mut types[i];
			ty.data.set(TypeData::Uninit {
				name: string_heap.intern(get_string_from_heap(strings, def.type_name)?),
				namespace: string_heap.intern(get_string_from_heap(strings, def.type_namespace)?),
			});

			if def.flags.contains(TypeAttributes::INTERFACE) {
				ty.kind = TypeKind::Interface;
			}
			else if def.flags.contains(TypeAttributes::CLASS) {
				ty.kind = TypeKind::Class;
			}
			else {
				unimplemented!();
			}
		}

		Ok(types)
	}
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum GenericTypeInstantiationError {
	TypeIsNotLoaded,
	TypeIsNotGeneric,
	InvalidGenericParameterCount,
}

pub fn fmt_display_types(types: &[&Type], f: &mut Formatter<'_>) -> std::fmt::Result {
	let mut dbg = f.debug_list();
	for ty in types {
		dbg.entry(&format_args!("{ty}"));
	}
	dbg.finish()
}
