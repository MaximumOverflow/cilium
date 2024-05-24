use std::io::{Cursor, Read};
use std::sync::Arc;

use bitflags::bitflags;
use derivative::Derivative;
use paste::paste;

use cilium_derive::FromRepr;

use crate::raw::heaps::{BlobIndex, GuidIndex, StringIndex};
use crate::raw::heaps::table::private::GetTable;
use crate::raw::indices::coded_index::*;
use crate::raw::indices::sizes::{IndexSizes, SizeOf};
use crate::utilities::FromByteStream;
use crate::utilities::impl_from_byte_stream;
use crate::utilities::enumerate_set_bits;

macro_rules! define_flags {
	() => {};
    (
		$(#[$outer:meta])*
        $vis:vis struct $BitFlags:ident: $T:ty {
            $(
                $(#[$inner:ident $($args:tt)*])*
                const $Flag:tt = $value:expr;
            )*
        }

        $($t:tt)*
	) => {
		bitflags! {
			$(#[$outer])*
			$vis struct $BitFlags: $T {
				$(
					$(#[$inner $($args)*])*
					const $Flag = $value;
				)*
			}
		}

		impl SizeOf<$BitFlags> for IndexSizes {
			fn size_of(&self) -> usize {
				std::mem::size_of::<$BitFlags>()
			}
		}

		impl_from_byte_stream!($BitFlags);

		define_flags!($($t)*);
	};
}

macro_rules! size_of {
    (u8, $sizes: expr) => { 1 };
    (u16, $sizes: expr) => { 2 };
    (u32, $sizes: expr) => { 4 };
    (u64, $sizes: expr) => { 8 };
    (GuidIndex, $sizes: expr) => { $sizes.guid };
    (BlobIndex, $sizes: expr) => { $sizes.blob };
    (StringIndex, $sizes: expr) => { $sizes.string };
    ($ty: ty, $sizes: expr) => { <IndexSizes as SizeOf<$ty>>::size_of($sizes) };
}

macro_rules! read_fn {
	($row: ident, { $($field: ident: $ty: ty $(=> |$($args:ident),*| { $($stmts:tt)* })? ),* }) => {
		fn read(cursor: &mut Cursor<&[u8]>, idx_sizes: &IndexSizes) -> std::io::Result<$row> {
			Ok(
				$row {
					$(
						$field: read_fn!(cursor, idx_sizes, { $field: $ty } $(=> |$($args),*| { $($stmts)* })? )
					),*
				}
			)
		}
	};
	($cursor: ident, $idx_sizes: ident, { $field: ident: $ty: ty }) => {
		<$ty>::read($cursor, $idx_sizes.as_ref())?
	};
    ($cursor: ident, $idx_sizes: ident, { $field: ident: $ty: ty } => |$($args:ident),*| { $($stmts:tt)* }) => {
		{
			let fld_read = |$($args),*| { $($stmts)* };
			fld_read($cursor, $idx_sizes)?
		}
	};
}

macro_rules! decl_tables {
    (
		[$($enum_name: ident = $enum_discriminant: literal),*]
		$(
			$vis: vis struct $row: ident: $discriminant: literal {
				$(
					$fld_vis: vis $field: ident: $ty: ty $(=> |$($args:ident),*| { $($stmts:tt)* })?,
				)*
			}
		)*
	)=> {
		paste! {
			$(
				#[derive(Copy, Clone)]
				#[allow(dead_code)]
				$vis struct $row {
					$(
						$fld_vis $field: $ty,
					)*
				}

				impl $row {
					pub fn calc_size(sizes: &IndexSizes) -> usize {
						let fields = [$(size_of!($ty, sizes)),*];
						fields.into_iter().sum()
					}
				}

				impl FromByteStream for $row {
					type Deps = IndexSizes;
					fn read(stream: &mut Cursor<&[u8]>, deps: &Self::Deps) -> std::io::Result<Self> {
						read_fn! {
							$row,
							{ $($field: $ty $(=> |$($args),*| { $($stmts)* })? ),* }
						}
						read(stream, deps)
					}
				}

				#[derive(Clone)]
				#[derive(Derivative)] // Temporary
				#[derivative(Debug)]
				$vis struct [<$row Table>]<'l> {
					len: usize,
					row_size: usize,
					#[derivative(Debug="ignore")]
					data: &'l [u8],
					#[derivative(Debug="ignore")]
					idx_sizes: Arc<IndexSizes>,
				}

				impl<'l> [<$row Table>]<'l> {
					#[inline]
					pub const fn len(&self) -> usize {
						self.len
					}

					#[inline]
					pub fn rows(&'l self) -> impl Iterator<Item=std::io::Result<$row>> + 'l {
						let mut cursor = Cursor::new(self.data);
						(0..self.len).map(move |_| $row::read(&mut cursor, &self.idx_sizes))
					}

					pub fn get(&'l self, idx: usize) -> std::io::Result<$row> {
						let offset = self.row_size * idx;
						let Some(data) = self.data.get(offset..offset+self.row_size) else {
							return Err(std::io::ErrorKind::InvalidInput.into());
						};
						let mut cursor = Cursor::new(data);
						$row::read(&mut cursor, &self.idx_sizes)
					}
				}

				impl Default for [<$row Table>]<'_> {
					fn default() -> Self {
						Self {
							len: 0,
							row_size: 0,
							data: &[],
							idx_sizes: IndexSizes::zero(),
						}
					}
				}

				#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
				$vis struct [<$row Index>](usize);

				impl [<$row Index>] {
					#[inline]
					pub const fn new(idx: Option<usize>) -> Self {
						match idx {
							None => Self(0),
							Some(idx) => Self(idx + 1),
						}
					}

					#[inline]
					pub const fn idx(&self) -> Option<usize> {
						match self.0 {
							0 => None,
							_ => Some(self.0 - 1),
						}
					}
				}

				impl SizeOf<[<$row Index>]> for IndexSizes {
					fn size_of(&self) -> usize {
						self.tables[TableKind::$row as usize]
					}
				}

				impl FromByteStream for [<$row Index>] {
					type Deps = IndexSizes;
					fn read(stream: &mut Cursor<&[u8]>, deps: &Self::Deps) -> std::io::Result<Self> {
						let table_size = <IndexSizes as SizeOf<[<$row Index>]>>::size_of(deps);
						let size = 2 + 2 * (table_size > 65536) as usize;
						let mut value = 0usize.to_ne_bytes();
						stream.read_exact(&mut value[..size])?;
						Ok(Self(usize::from_le_bytes(value)))
					}
				}

				impl<'l> GetTable<$row> for TableHeap<'l> {
					type Table = [<$row Table>]<'l>;
					fn get_table(&self) -> Option<&Self::Table> {
						self.tables.iter().find_map(|t| match t {
							Table::$row(t) => Some(t),
							_ => None,
						})
					}
				}
			)*

			#[derive(Debug, Clone)]
			pub enum Table<'l> {
				$($row([<$row Table>]<'l>)),*
			}

			#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, FromRepr)]
			pub enum TableKind {
				$($row = $discriminant,)*
				$($enum_name = $enum_discriminant,)*
			}

			impl<'l> TryFrom<&'l [u8]> for TableHeap<'l> {
				type Error = std::io::Error;
				#[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
				fn try_from(value: &'l [u8]) -> Result<Self, Self::Error> {
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

					let mut stream = Cursor::new(value);
					let Header {
						heap_sizes,
						valid,
						minor_version,
						major_version,
						..
					} = Header::read(&mut stream, &())?;

					let table_count = valid.count_ones() as usize;
					let mut table_sizes = vec![0u32; 55];

					for i in enumerate_set_bits(valid) {
						let mut bytes = 0u32.to_ne_bytes();
						stream.read_exact(&mut bytes)?;
						table_sizes[i] = u32::from_le_bytes(bytes);
					}

					let mut offset = stream.position() as usize;
					let idx_sizes = IndexSizes::new(heap_sizes, table_sizes.as_slice().try_into().unwrap());

					let mut tables: Vec<Table> = Vec::with_capacity(table_count);
					for i in enumerate_set_bits(valid) {
						let len = table_sizes[i] as usize;
						let Some(kind) = TableKind::from_repr(i) else {
							return Err(std::io::ErrorKind::InvalidData.into());
						};

						#[rustfmt::skip]
						tables.push(match kind {
							$(
								TableKind::$row => Table::$row({
									let row_size = $row::calc_size(&idx_sizes);
									let table_size = row_size * len;
									let Some(data) = value.get(offset..offset+table_size) else {
										return Err(std::io::ErrorKind::InvalidData.into());
									};
									offset += table_size;

									[<$row Table>] {
										len,
										row_size,
										data,
										idx_sizes: idx_sizes.clone(),
									}
								}),
							)*
							_ => todo!("Unimplemented table {kind:?}")
						});
					}

					Ok(Self {
						major_version,
						minor_version,
						tables,
					})
				}
			}
		}
	};
}

define_flags! {
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

		// #### Additional Attributes ####
		/// CLI provides 'special' behavior, depending upon the name of the Type.
		const RTSpecialName = 0x00000800;
		/// Type has security associate with it.
		const HasSecurity = 0x00040000;
		/// This ExportedType entry is a type forwarder.
		const IsTypeForwarder = 0x00200000;
	}

	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct FieldAttributes: u16 {
		// #### Accessibility attributes ####
		/// Use this mask to retrieve access information.
		const FIELD_ACCESS_MASK = 0x0007;
		/// Member not referenceable.
		const COMPILER_CONTROLLED = 0x0000;
		/// Accessible only by the parent type.
		const PRIVATE = 0x0001;
		/// Accessible by sub-types only in this Assembly.
		const FAMILY_AND_ASSEMBLY = 0x0002;
		/// Accessibly by anyone in the Assembly.
		const ASSEMBLY = 0x0003;
		/// Accessible only by type and sub-types.
		const FAMILY = 0x0004;
		/// Accessibly by sub-types anywhere, plus anyone in assembly.
		const FAMILY_OR_ASSEMBLY = 0x0005;
		/// Accessibly by anyone who has visibility to this scope field contract attributes.
		const PUBLIC = 0x0006;
		/// Defined on type, else per instance.
		const STATIC = 0x0010;
		/// Field can only be initialized, not written to after init.
		const INIT_ONLY = 0x0020;
		/// Value is compile time constant.
		const LITERAL = 0x0040;
		/// Reserved (to indicate this field should not be serialized when type is remoted).
		const NOT_SERIALIZED = 0x0080;
		/// Field is special.
		const SPECIAL_NAME = 0x0200;

		// #### Interop Attribute ####
		/// Implementation is forwarded through PInvoke.
		const PINVOKE_IMPL = 0x2000;

		// #### Additional Attributes ####
		/// CLI provides 'special' behavior, depending upon the name of the field.
		const RT_SPECIAL_NAME = 0x0400;
		/// Field has marshalling information.
		const HAS_FIELD_MARSHAL = 0x1000;
		/// Field has default.
		const HAS_DEFAULT = 0x8000;
		/// Field has RVA.
		const HAS_FIELD_RVA = 0x0100;
	}

	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct AssemblyFlags: u32 {
		/// The assembly reference holds the full (unhashed) public key.
		const PUBLIC_KEY = 0x0001;
		/// The implementation of this assembly used at runtime is not expected to match the version seen at compile time.
		const RETARGETABLE = 0x0100;
		/// Reserved (a conforming implementation of the CLI can ignore this setting on read; some implementations might use this bit to indicate that a CIL-to-native-code compiler should not generate optimized code).
		const DISABLE_JIT_COMPILE_OPTIMIZER = 0x4000;
		/// Reserved (a conforming implementation of the CLI can ignore this setting on read; some implementations might use this bit to indicate that a CIL-to-native-codecompiler should generate CIL-to-native code map).
		const ENABLE_JIT_COMPILE_TRACKING = 0x8000;
	}

	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct MethodAttributes: u16 {
		//TODO
	}

	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct MethodImplAttributes: u16 {
		//TODO
	}

	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct ParamAttributes: u16 {
		//TODO
	}

	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct EventAttributes: u16 {
		//TODO
	}

	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct PropertyAttributes: u16 {
		//TODO
	}

	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct MethodSemanticsAttributes: u16 {
		//TODO
	}

	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct PInvokeAttributes: u16 {
		//TODO
	}

	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct ManifestResourceAttributes: u32 {
		//TODO
	}

	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct GenericParamAttributes: u16 {
		//TODO
	}

	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct FileAttributes: u32 {
		//TODO
	}
}

decl_tables! {
	[
		Document = 0x30,
		MethodDebugInformation = 0x31,
		LocalScope = 0x32,
		LocalVariable = 0x33,
		LocalConstant = 0x34,
		ImportScope = 0x35,
		StateMachineMethod = 0x36,
		CustomDebugInformation = 0x37
	]

	pub struct Module: 0x00 {
		pub generation: u16,
		pub name: StringIndex,
		pub mv_id: GuidIndex,
		pub enc_id: GuidIndex,
		pub enc_base_id: GuidIndex,
	}

	pub struct TypeRef: 0x01 {
		pub resolution_scope: ResolutionScope,
		pub name: StringIndex,
		pub namespace: StringIndex,
	}

	pub struct TypeDef: 0x02 {
		pub flags: TypeAttributes,
		pub name: StringIndex,
		pub namespace: StringIndex,
		pub extends: TypeDefOrRef,
		pub field_list: FieldIndex,
		pub method_list: MethodDefIndex,
	}

	pub struct Field: 0x04 {
		pub flags: FieldAttributes,
		pub name: StringIndex,
		pub signature: BlobIndex,
	}

	pub struct MethodDef: 0x06 {
		pub rva: u32,
		pub impl_flags: MethodAttributes,
		pub flags: MethodAttributes,
		pub name: StringIndex,
		pub signature: BlobIndex,
		pub param_list: ParamIndex,
	}

	pub struct Param: 0x08 {
		pub flags: ParamAttributes,
		pub sequence: u16,
		pub name: StringIndex,
	}

	pub struct InterfaceImpl: 0x09 {
		pub class: TypeDefIndex,
		pub interface: TypeDefOrRef,
	}

	pub struct MemberRef: 0x0A {
		pub class: MemberRefParent,
		pub name: StringIndex,
		pub signature: BlobIndex,
	}

	pub struct Constant: 0x0B {
		pub ty: [u8; 2],
		pub parent: HasConstant,
		pub value: BlobIndex,
	}

	pub struct CustomAttribute: 0x0C {
		pub parent: HasCustomAttribute,
		pub ty: CustomAttributeType,
		pub value: BlobIndex,
	}

	pub struct FieldMarshal: 0x0D {
		pub parent: HasFieldMarshal,
		pub native_type: BlobIndex,
	}

	pub struct DeclSecurity: 0x0E {
		action: u16, // TODO
		parent: HasDeclSecurity,
		permission_set: BlobIndex,
	}

	pub struct ClassLayout: 0x0F {
		pub packing_size: u16,
		pub class_size: u32,
		pub parent: TypeDefIndex,
	}

	pub struct FieldLayout: 0x10 {
		pub offset: u32,
		pub field: FieldIndex,
	}

	pub struct StandAloneSig: 0x11 {
		pub signature: BlobIndex,
	}

	pub struct EventMap: 0x12 {
		pub parent: TypeDefIndex,
		pub event_list: EventIndex,
	}

	pub struct Event: 0x14 {
		pub flags: EventAttributes,
		pub name: StringIndex,
		pub ty: TypeDefOrRef,
	}

	pub struct PropertyMap: 0x15 {
		pub parent: TypeDefIndex,
		pub property_list: PropertyIndex,
	}

	pub struct Property: 0x17 {
		pub flags: PropertyAttributes,
		pub name: StringIndex,
		pub ty: BlobIndex,
	}

	pub struct MethodSemantics: 0x18 {
		pub flags: MethodSemanticsAttributes,
		pub method: MethodDefIndex,
		pub association: HasSemantics,
	}

	pub struct MethodImpl: 0x19 {
		pub class: TypeDefIndex,
		pub body: MethodDefOrRef,
		pub declaration: MethodDefOrRef,
	}

	pub struct ModuleRef: 0x1A {
		pub name: StringIndex,
	}

	pub struct TypeSpec: 0x1B {
		pub signature: BlobIndex,
	}

	pub struct ImplMap: 0x1C {
		pub flags: PInvokeAttributes,
		pub member_forwarded: MemberForwarded,
		pub import_name: StringIndex,
		pub import_scope: ModuleRefIndex,
	}

	pub struct FieldRVA: 0x1D {
		pub rva: u32,
		pub field: FieldIndex,
	}

	pub struct Assembly: 0x20 {
		pub hash_algorithm: AssemblyHashAlgorithm,
		pub major_version: u16,
		pub minor_version: u16,
		pub build_number: u16,
		pub revision_number: u16,
		pub flags: AssemblyFlags,
		pub public_key: BlobIndex,
		pub name: StringIndex,
		pub culture: StringIndex,
	}

	pub struct AssemblyRef: 0x23 {
		pub major_version: u16,
		pub minor_version: u16,
		pub build_number: u16,
		pub revision_number: u16,
		pub flags: AssemblyFlags,
		pub public_key: BlobIndex,
		pub name: StringIndex,
		pub culture: StringIndex,
		pub hash_value: BlobIndex,
	}

	pub struct File: 0x26 {
		flags: FileAttributes,
		name: StringIndex,
		hash_value: BlobIndex,
	}

	pub struct ExportedType: 0x27 {
		pub flags: TypeAttributes,
		pub type_def: TypeDefIndex => |cursor, _idx_sizes| {
			let value = u32::read(cursor, &())?;
			Ok::<_, std::io::Error>(TypeDefIndex(value as usize))
		},
		pub name: StringIndex,
		pub namespace: StringIndex,
		pub implementation: Implementation,
	}

	pub struct ManifestResource: 0x28 {
		pub offset: u32,
		pub flags: ManifestResourceAttributes,
		pub name: StringIndex,
		pub implementation: Implementation,
	}

	pub struct NestedClass: 0x29 {
		pub nested_class: TypeDefIndex,
		pub enclosing_class: TypeDefIndex,
	}

	pub struct GenericParam: 0x2A {
		pub number: u16,
		pub flags: GenericParamAttributes,
		pub owner: TypeOrMethodDef,
		pub name: StringIndex,
	}

	pub struct MethodSpec: 0x2B {
		pub method: MethodDefOrRef,
		pub instantiation: BlobIndex,
	}

	pub struct GenericParamConstraint: 0x2C {
		pub owner: GenericParamIndex,
		pub constraint: TypeDefOrRef,
	}
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, FromRepr)]
pub enum AssemblyHashAlgorithm {
	None = 0x0000,
	MD5 = 0x8003,
	SHA1 = 0x8004,
	SHA256 = 0x800C,
	SHA384 = 0x800D,
	SHA512 = 0x800E,
}

impl SizeOf<AssemblyHashAlgorithm> for IndexSizes {
	fn size_of(&self) -> usize {
		std::mem::size_of::<AssemblyHashAlgorithm>()
	}
}

impl_from_byte_stream!(AssemblyHashAlgorithm);

#[derive(Debug)]
pub struct TableHeap<'l> {
	major_version: u8,
	minor_version: u8,
	tables: Vec<Table<'l>>,
}

impl<'l> TableHeap<'l> {
	pub fn major_version(&self) -> u8 {
		self.major_version
	}
	pub fn minor_version(&self) -> u8 {
		self.minor_version
	}
	#[allow(private_bounds)]
	pub fn get_table<T>(&self) -> Option<&<Self as GetTable<T>>::Table> where Self: GetTable<T> {
		GetTable::get_table(self)
	}
}

mod private {
	pub trait GetTable<T> {
		type Table;
		fn get_table(&self) -> Option<&Self::Table>;
	}
}
