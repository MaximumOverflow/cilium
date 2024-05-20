pub mod metadata_token {
	use std::fmt::{Debug, Formatter};
	use std::io::{Cursor, ErrorKind};

	use crate::utilities::FromByteStream;

	macro_rules! define_metadata_token {
		($($id: ident = $discriminant: literal),*) => {
			#[repr(u32)]
			#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
			pub enum MetadataTokenKind {
				$($id = $discriminant),*
			}

			#[repr(transparent)]
			#[derive(Copy, Clone, Eq, PartialEq, Hash)]
			pub struct MetadataToken(u32);

			impl MetadataToken {
				pub fn kind(&self) -> MetadataTokenKind {
					let discriminant = (self.0 & 0xFF000000) >> 24;
					match discriminant {
						$($discriminant => MetadataTokenKind::$id,)*
						_ => unreachable!(),
					}
				}

				#[inline]
				pub fn index(&self) -> usize {
					(self.0 & 0x00FFFFFF) as usize
				}

				#[inline]
				pub fn raw(&self) -> u32 {
					self.0
				}
			}

			impl TryFrom<u32> for MetadataToken {
				type Error = ();
				fn try_from(value: u32) -> Result<Self, Self::Error> {
					let discriminant = (value & 0xFF000000) >> 24;
					match discriminant {
						$($discriminant => Ok(Self(value)),)*
						_ => Err(())
					}
				}
			}

			$(
				#[repr(transparent)]
				#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
				pub struct $id(pub usize);

				impl From<$id> for MetadataToken {
					fn from(value: $id) -> Self {
						MetadataToken(((MetadataTokenKind::$id as u32) << 24) | value.0 as u32)
					}
				}

				impl TryFrom<MetadataToken> for $id {
					type Error = ();
					fn try_from(value: MetadataToken) -> Result<Self, Self::Error> {
						match value.kind() {
							MetadataTokenKind::$id => Ok(Self(value.index())),
							_ => Err(()),
						}
					}
				}
			)*
		};
	}
	impl Debug for MetadataToken {
		fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
			write!(f, "MetadataToken::{:?}(", self.kind())?;
			self.index().fmt(f)?;
			write!(f, ")")
		}
	}

	impl FromByteStream for MetadataToken {
		type Deps = ();
		fn read(stream: &mut Cursor<&[u8]>, _: &Self::Deps) -> std::io::Result<Self> {
			let value = u32::read(stream, &())?;
			MetadataToken::try_from(value).map_err(|_| ErrorKind::InvalidData.into())
		}
	}

	define_metadata_token! {
		Module = 0x00,
		TypeRef = 0x01,
		TypeDef = 0x02,
		Field = 0x04,
		MethodDef = 0x06,
		Param = 0x08,
		InterfaceImpl = 0x09,
		MemberRef = 0x0a,
		CustomAttribute = 0x0c,
		DeclSecurity = 0x0e,
		StandAloneSig = 0x11,
		Event = 0x14,
		Property = 0x17,
		ModuleRef = 0x1a,
		TypeSpec = 0x1b,
		Assembly = 0x20,
		AssemblyRef = 0x23,
		File = 0x26,
		ExportedType = 0x27,
		ManifestResource = 0x28,
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

		String = 0x70
	}
}

pub mod coded_index {
	use std::io::{Cursor, ErrorKind, Read};

	use crate::raw::heaps::table::TableKind;
	use std::fmt::{Debug, Formatter};
	use crate::raw::indices::metadata_token::{MetadataTokenKind, MetadataToken};
	use crate::raw::indices::sizes::CodedIndexSizes;
	use crate::utilities::FromByteStream;

	macro_rules! define_coded_index {
		($($id: ident: [$($variant: ident),*]),*) => {
			#[repr(u32)]
			#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
			pub enum CodedIndexKind {
				$($id),*
			}

			$(
				#[repr(transparent)]
				#[derive(Copy, Clone, Eq, PartialEq, Hash)]
				pub struct $id(u32);

				impl Debug for $id {
					fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
						let token: MetadataToken = (*self).into();
						write!(f, "{}(", stringify!($id))?;
						self.0.fmt(f)?;
						write!(f, ") | ")?;
						token.fmt(f)
					}
				}

				impl TryFrom<u32> for $id {
					type Error = ();
					fn try_from(value: u32) -> Result<Self, Self::Error> {
						match CodedIndexKind::$id.is_valid(value) {
							false => Err(()),
							true => Ok(Self(value)),
						}
					}
				}

				impl FromByteStream for $id {
					type Deps = CodedIndexSizes;
					fn read(stream: &mut Cursor<&[u8]>, sizes: &Self::Deps) -> std::io::Result<Self> {
						let size = sizes.0[CodedIndexKind::$id as usize];
						let mut bytes = 0u32.to_ne_bytes();
						stream.read_exact(&mut bytes[..size])?;
						let value = u32::from_le_bytes(bytes);
						Self::try_from(value).map_err(|_| ErrorKind::InvalidData.into())
					}
				}

				impl From<$id> for MetadataToken {
					fn from(value: $id) -> Self {
						const BITS: u32 = CodedIndexKind::$id.mask_bits();
						let token = CodedIndexKind::$id.token_kind(value.0);
						let val = ((token as u32) << 24) | value.0 >> BITS;
						MetadataToken::try_from(val).unwrap()
					}
				}

				$(
					impl From<$id> for crate::raw::indices::metadata_token::$variant {
						fn from(value: $id) -> Self {
							use crate::raw::indices::metadata_token::*;
							let token = MetadataToken::from(value);
							$variant::try_from(token).unwrap()
						}
					}
				)*
			)*

			const TABLES: &[&[TableKind]] = &[$(&[$(TableKind::$variant),*]),*];
			const TOKENS: &[&[MetadataTokenKind]] = &[$(&[$(MetadataTokenKind::$variant),*]),*];
		};
	}

	define_coded_index! {
		TypeDefOrRef: [TypeDef, TypeRef, TypeSpec],
		HasConstant: [Field, Param, Property],
		HasCustomAttribute: [
			MethodDef, Field, TypeRef, TypeDef, Param, InterfaceImpl, MemberRef,
			Module, DeclSecurity, Property, Event, StandAloneSig, ModuleRef,
			TypeSpec, Assembly, AssemblyRef, File, ExportedType,
			ManifestResource, GenericParam, GenericParamConstraint, MethodSpec
		],
		HasFieldMarshal: [Field, Param],
		HasDeclSecurity: [TypeDef, MethodDef, Assembly],
		MemberRefParent: [TypeDef, TypeRef, ModuleRef, MethodDef, TypeSpec],
		HasSemantics: [Event, Property],
		MethodDefOrRef: [MethodDef, MemberRef],
		MemberForwarded: [Field, MethodDef],
		Implementation: [File, AssemblyRef, ExportedType],
		CustomAttributeType: [MethodDef, MemberRef],
		ResolutionScope: [Module, ModuleRef, AssemblyRef, TypeRef],
		TypeOrMethodDef: [TypeDef, MethodDef],
		HasCustomDebugInformation: [
			MethodDef, Field, TypeRef, TypeDef, Param, InterfaceImpl, MemberRef,
			Module, DeclSecurity, Property, Event, StandAloneSig, ModuleRef,
			TypeSpec, Assembly, AssemblyRef, File, ExportedType,
			ManifestResource, GenericParam, GenericParamConstraint, MethodSpec,
			Document, LocalScope, LocalVariable, LocalConstant, ImportScope
		]
	}

	impl CodedIndexKind {
		pub const fn get_size(&self, table_sizes: &[u32; 64]) -> usize {
			let mut i = 0;
			let mut max = 0;
			let bits = self.mask_bits();
			let tables = TABLES[*self as usize];
			while i < tables.len() {
				let table = tables[i];
				let size = table_sizes[table as usize] as usize;
				if max < size {
					max = size;
				}
				i += 1;
			}

			2 + 2 * (max > (1 << (16 - bits))) as usize
		}

		pub const fn mask(&self) -> u32 {
			match self {
				CodedIndexKind::CustomAttributeType => 0x7,
				_ => {
					let tokens = TABLES[*self as usize];
					match tokens.len() {
						0 | 1 => 0,
						_ => u32::MAX.overflowing_shr((tokens.len() as u32 - 1).leading_zeros()).0,
					}
				},
			}
		}

		pub const fn mask_bits(&self) -> u32 {
			match self {
				CodedIndexKind::CustomAttributeType => 0x3,
				_ => {
					let tokens = TABLES[*self as usize];
					32 - (tokens.len() as u32 - 1).leading_zeros()
				},
			}
		}

		pub const fn is_valid(&self, value: u32) -> bool {
			let discriminant = value & self.mask();
			match self {
				CodedIndexKind::CustomAttributeType => matches!(discriminant, 2 | 3),
				_ => {
					let tables = TABLES[*self as usize];
					((value & self.mask()) as usize) < tables.len()
				},
			}
		}

		pub const fn token_kind(&self, value: u32) -> MetadataTokenKind {
			let mask = self.mask();
			let discriminant = value & mask;
			match self {
				CodedIndexKind::CustomAttributeType => match discriminant {
					2 => MetadataTokenKind::MethodDef,
					3 => MetadataTokenKind::MemberRef,
					_ => unreachable!(),
				},
				_ => TOKENS[*self as usize][discriminant as usize],
			}
		}
	}
}

pub(crate) mod sizes {
	use std::alloc::Layout;

	use crate::raw::indices::coded_index::CodedIndexKind;

	pub struct IndexSizes {
		guid: GuidIndexSize,
		blob: BlobIndexSize,
		string: StringIndexSize,
		coded: CodedIndexSizes,
		tables: TableIndexSizes,
	}

	pub struct GuidIndexSize(pub(crate) usize);
	pub struct BlobIndexSize(pub(crate) usize);
	pub struct StringIndexSize(pub(crate) usize);
	pub struct CodedIndexSizes(pub(crate) [usize; 14]);
	pub struct TableIndexSizes(pub(crate) [usize; 64]);

	impl IndexSizes {
		pub fn new(heap_sizes: u8, table_lens: &[u32; 64]) -> Box<Self> {
			unsafe {
				let ptr = std::alloc::alloc(Layout::new::<Self>()) as *mut Self;
				let mut val = Box::from_raw(ptr);

				val.blob = BlobIndexSize(2 + 2 * ((heap_sizes & 0x4) != 0) as usize);
				val.guid = GuidIndexSize(2 + 2 * ((heap_sizes & 0x2) != 0) as usize);
				val.string = StringIndexSize(2 + 2 * ((heap_sizes & 0x1) != 0) as usize);

				for (size, len) in val.tables.0.iter_mut().zip(table_lens) {
					*size = 2 + 2 * (*len > 65536) as usize
				}

				for i in 0..14 {
					let kind: CodedIndexKind = std::mem::transmute(i as u32);
					val.coded.0[i] = kind.get_size(table_lens);
				}

				val
			}
		}
	}
	impl AsRef<()> for IndexSizes {
		#[inline(always)]
		fn as_ref(&self) -> &() {
			&()
		}
	}
	impl AsRef<IndexSizes> for IndexSizes {
		#[inline(always)]
		fn as_ref(&self) -> &IndexSizes {
			self
		}
	}
	impl AsRef<GuidIndexSize> for IndexSizes {
		#[inline(always)]
		fn as_ref(&self) -> &GuidIndexSize {
			&self.guid
		}
	}
	impl AsRef<BlobIndexSize> for IndexSizes {
		#[inline(always)]
		fn as_ref(&self) -> &BlobIndexSize {
			&self.blob
		}
	}
	impl AsRef<StringIndexSize> for IndexSizes {
		#[inline(always)]
		fn as_ref(&self) -> &StringIndexSize {
			&self.string
		}
	}
	impl AsRef<CodedIndexSizes> for IndexSizes {
		#[inline(always)]
		fn as_ref(&self) -> &CodedIndexSizes {
			&self.coded
		}
	}
	impl AsRef<TableIndexSizes> for IndexSizes {
		#[inline(always)]
		fn as_ref(&self) -> &TableIndexSizes {
			&self.tables
		}
	}
}
