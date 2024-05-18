use std::fmt::Debug;

use crate::utilities::FromByteStream;

pub mod metadata_token {
	use std::fmt::{Debug, Formatter};
	use std::io::{Cursor, ErrorKind};

	use crate::FromByteStream;

	macro_rules! define_metadata_token {
		($($id: ident = $discriminant: literal),*) => {
			#[repr(u32)]
			#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
			pub enum MetadataTokenKind {
				$($id = $discriminant),*
			}

			#[repr(transparent)]
			#[derive(Copy, Clone, Eq, PartialEq, Hash)]
			pub struct RawMetadataToken(u32);

			impl RawMetadataToken {
				pub fn kind(&self) -> MetadataTokenKind {
					let discriminant = (self.0 & 0xFF000000) >> 24;
					match discriminant {
						$($discriminant => MetadataTokenKind::$id,)*
						_ => unreachable!(),
					}
				}

				pub fn index(&self) -> usize {
					(self.0 & 0x00FFFFFF) as usize
				}
			}

			impl TryFrom<u32> for RawMetadataToken {
				type Error = ();
				fn try_from(value: u32) -> Result<Self, Self::Error> {
					let discriminant = (value & 0xFF000000) >> 24;
					match discriminant {
						$($discriminant => Ok(Self(value)),)*
						_ => Err(())
					}
				}
			}

			#[repr(u32)]
			#[derive(Copy, Clone, Eq, PartialEq, Hash)]
			pub enum MetadataToken {
				$($id($id)),*
			}

			impl Debug for MetadataToken {
				fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
					match self {
						$(Self::$id(v) => write!(f, "MetadataToken::{:?}", v)),*
					}
				}
			}

			impl From<RawMetadataToken> for MetadataToken {
				fn from(value: RawMetadataToken) -> Self {
					match value.kind() {
						$(MetadataTokenKind::$id => Self::$id($id((value.0 & 0x00FFFFFF) as usize))),*
					}
				}
			}

			impl From<MetadataToken> for RawMetadataToken {
				fn from(value: MetadataToken) -> Self {
					match value {
						$(MetadataToken::$id(idx) => Self(
							((MetadataTokenKind::$id as u32) << 24) | idx.0 as u32
						)),*
					}
				}
			}

			$(
				#[repr(transparent)]
				#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
				pub struct $id(usize);

				impl TryFrom<RawMetadataToken> for $id {
					type Error = ();
					fn try_from(value: RawMetadataToken) -> Result<Self, Self::Error> {
						match value.kind() {
							MetadataTokenKind::$id => Ok(Self(value.index())),
							_ => Err(()),
						}
					}
				}

				impl TryFrom<MetadataToken> for $id {
					type Error = ();
					fn try_from(value: MetadataToken) -> Result<Self, Self::Error> {
						match value {
							MetadataToken::$id(idx) => Ok(Self(idx.0)),
							_ => Err(()),
						}
					}
				}
			)*
		};
	}
	impl Debug for RawMetadataToken {
		fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
			write!(f, "RawMetadataToken::{:?}", self.kind())?;
			let mut dbg = f.debug_tuple("");
			dbg.field(&self.index());
			dbg.finish()
		}
	}

	impl FromByteStream for RawMetadataToken {
		fn read(stream: &mut Cursor<&[u8]>) -> std::io::Result<Self> {
			let value = u32::read(stream)?;
			RawMetadataToken::try_from(value).map_err(|_| ErrorKind::InvalidData.into())
		}
	}

	impl FromByteStream for MetadataToken {
		fn read(stream: &mut Cursor<&[u8]>) -> std::io::Result<Self> {
			let value = u32::read(stream)?;
			MetadataToken::try_from(value).map_err(|_| ErrorKind::InvalidData.into())
		}
	}

	impl TryFrom<u32> for MetadataToken {
		type Error = ();
		fn try_from(value: u32) -> Result<Self, Self::Error> {
			let raw = RawMetadataToken::try_from(value)?;
			Ok(MetadataToken::from(raw))
		}
	}

	define_metadata_token! {
		Module = 0x00,
		TypeRef = 0x01,
		TypeDef = 0x02,
		Field = 0x04,
		Method = 0x06,
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
	use crate::heaps::table::TableKind;
	use crate::indices::metadata_token::{MetadataTokenKind, RawMetadataToken};

	macro_rules! define_coded_index {
		($($id: ident: [$($variant: ident),*]),*) => {
			#[repr(u32)]
			#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
			pub enum CodedIndexKind {
				$($id),*
			}

			$(
				#[repr(transparent)]
				#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
				pub struct $id(u32);

				impl TryFrom<u32> for $id {
					type Error = ();
					fn try_from(value: u32) -> Result<Self, Self::Error> {
						const MASK: u32 = CodedIndexKind::$id.mask();
						let tables = TABLES[CodedIndexKind::$id as usize];
						match ((value & MASK) as usize) < tables.len() {
							false => Err(()),
							true => Ok(Self(value)),
						}
					}
				}

				impl From<$id> for crate::indices::metadata_token::RawMetadataToken {
					fn from(value: $id) -> Self {
						const MASK: u32 = CodedIndexKind::$id.mask();
						const BITS: u32 = CodedIndexKind::$id.mask_bits();
						let tokens = TOKENS[CodedIndexKind::$id as usize];
						let token = tokens[(value.0 & MASK) as usize];
						let val = ((token as u32) << 24) | value.0 >> BITS;
						RawMetadataToken::try_from(val).unwrap()
					}
				}

				$(
					impl From<$id> for crate::indices::metadata_token::$variant {
						fn from(value: $id) -> Self {
							use crate::indices::metadata_token::*;
							let token = RawMetadataToken::from(value);
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
			Method, Field, TypeRef, TypeDef, Param, InterfaceImpl, MemberRef,
			Module, DeclSecurity, Property, Event, StandAloneSig, ModuleRef,
			TypeSpec, Assembly, AssemblyRef, File, ExportedType,
			ManifestResource, GenericParam, GenericParamConstraint, MethodSpec
		],
		HasFieldMarshal: [Field, Param],
		HasDeclSecurity: [TypeDef, Method, Assembly],
		MemberRefParent: [TypeDef, TypeRef, ModuleRef, Method, TypeSpec],
		HasSemantics: [Event, Property],
		MethodDefOrRef: [Method, MemberRef],
		MemberForwarded: [Field, Method],
		Implementation: [File, AssemblyRef, ExportedType],
		CustomAttributeType: [Method, MemberRef],
		ResolutionScope: [Module, ModuleRef, AssemblyRef, TypeRef],
		TypeOrMethodDef: [TypeDef, Method],
		HasCustomDebugInformation: [
			Method, Field, TypeRef, TypeDef, Param, InterfaceImpl, MemberRef,
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
				let size = table_sizes[tables[i] as usize] as usize;
				if max < size {
					max = size;
				}
				i += 1;
			}

			return 2 + 2 * (max > (1 << (16 - bits))) as usize
		}

		pub const fn mask(&self) -> u32 {
			let tokens = TABLES[*self as usize];
			u32::MAX.overflowing_shr((tokens.len() as u32).leading_zeros()).0
		}

		pub const fn mask_bits(&self) -> u32 {
			let tokens = TABLES[*self as usize];
			32 - (tokens.len() as u32).leading_zeros()
		}
	}
}

