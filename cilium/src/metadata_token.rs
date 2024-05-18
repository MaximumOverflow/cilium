use crate::utilities::{FromByteStream, impl_from_byte_stream};
use std::fmt::{Debug, Formatter};
use std::io::{ErrorKind, Cursor};

macro_rules! define_metadata_token {
    ($($id: ident = $discriminant: literal),*) => {
		#[repr(u32)]
		#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
		pub enum MetadataTokenKind {
			$($id = $discriminant),*
		}

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

			pub fn index(&self) -> usize {
				(self.0 & 0x00FFFFFF) as usize
			}
		}

		impl FromByteStream for MetadataToken {
			#[inline]
			fn read(stream: &mut Cursor<&[u8]>) -> std::io::Result<Self> {
				let value = u32::read(stream)?;
				MetadataToken::try_from(value).map_err(|_| ErrorKind::InvalidData.into())
			}
		}

		impl TryFrom<u32> for MetadataToken {
			type Error = ();
			#[inline(never)]
			fn try_from(value: u32) -> Result<Self, Self::Error> {
				let discriminant = (value & 0xFF000000) >> 24;
				match discriminant {
					$($discriminant => Ok(Self(value)),)*
					_ => Err(())
				}
			}
		}
	};
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
	Permission = 0x0e,
	Signature = 0x11,
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

impl Debug for MetadataToken {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		write!(f, "MetadataToken::{:?}", self.kind())?;
		let mut dbg = f.debug_tuple("");
		dbg.field(&self.index());
		dbg.finish()
	}
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum CodedIndexKind {
	TypeDefOrRef,
	HasConstant,
	HasCustomAttribute,
	HasFieldMarshal,
	HasDeclSecurity,
	MemberRefParent,
	HasSemantics,
	MethodDefOrRef,
	MemberForwarded,
	Implementation,
	CustomAttributeType,
	ResolutionScope,
	TypeOrMethodDef,
	HasCustomDebugInformation,
}


