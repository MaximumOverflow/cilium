use std::fmt::{Debug, Display, Formatter};
use std::io::Write;

use crate::raw::indices::metadata_token::MetadataToken;
use crate::schema::heaps::InternedString;
use crate::schema::method::Method;
use crate::schema::r#type::private::{get_type_discriminant, TypeDiscriminant, TypePrivate};

pub trait Type<'l>: TypePrivate + Display {
	fn write_as_blob(&self, stream: &mut dyn Write) -> std::io::Result<()>;

	fn __type_discriminant(&self) -> TypeDiscriminant {
		get_type_discriminant::<Self>()
	}
}

impl<'l> dyn Type<'l> {
	pub fn downcast<T: Type<'l>>(&self) -> Option<&T> {
		unsafe {
			match self.__type_discriminant() == get_type_discriminant::<T>() {
				false => None,
				true => Some(&*(self as *const Self as *const T)),
			}
		}
	}
}

impl<'l> Debug for &dyn Type<'l> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		Display::fmt(self, f)
	}
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Primitive {
	Void = 0x01,
	Bool = 0x02,
	Char = 0x03,
	Int8 = 0x04,
	Int16 = 0x06,
	Int32 = 0x08,
	Int64 = 0x0A,
	UInt8 = 0x05,
	UInt16 = 0x07,
	UInt32 = 0x09,
	UInt64 = 0x0B,
	Float = 0x0C,
	Double = 0x0D,
	String = 0x0E,
	NInt = 0x18,
	NUInt = 0x19,
}

impl Display for Primitive {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		match self {
			Primitive::Void => write!(f, "void"),
			Primitive::Bool => write!(f, "bool"),
			Primitive::Char => write!(f, "char"),
			Primitive::Int8 => write!(f, "sbyte"),
			Primitive::Int16 => write!(f, "short"),
			Primitive::Int32 => write!(f, "int"),
			Primitive::Int64 => write!(f, "long"),
			Primitive::UInt8 => write!(f, "byte"),
			Primitive::UInt16 => write!(f, "ushort"),
			Primitive::UInt32 => write!(f, "uint"),
			Primitive::UInt64 => write!(f, "ulong"),
			Primitive::Float => write!(f, "float"),
			Primitive::Double => write!(f, "double"),
			Primitive::String => write!(f, "string"),
			Primitive::NInt => write!(f, "nint"),
			Primitive::NUInt => write!(f, "nuint"),
		}
	}
}

impl TypePrivate for Primitive {}

impl Type<'_> for Primitive {
	fn write_as_blob(&self, stream: &mut dyn Write) -> std::io::Result<()> {
		stream.write_all(&[*self as u8])
	}
}

#[derive(Debug)]
pub struct Class<'l> {
	pub(crate) metadata_token: MetadataToken,
	pub(crate) name: InternedString<'l>,
	pub(crate) namespace: InternedString<'l>,
	pub(crate) fields: Vec<Field<'l>>,
	pub(crate) methods: Vec<Method<'l>>,
}

#[derive(Debug)]
pub struct Field<'l> {
	pub(crate) name: InternedString<'l>,
}

impl Display for Class<'_> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		match self.namespace.is_empty() {
			true => write!(f, "{}", self.name),
			false => write!(f, "{}.{}", self.namespace, self.name),
		}
	}
}

impl TypePrivate for Class<'_> {}

impl<'l> Type<'l> for Class<'l> {
	fn write_as_blob(&self, stream: &mut dyn Write) -> std::io::Result<()> {
		let mut buffer = [0u8; 5];
		buffer[0] = 0x15;
		buffer[1..5].copy_from_slice(&self.metadata_token.raw().to_le_bytes());
		stream.write_all(&buffer)
	}
}

#[derive(Debug)]
pub struct Interface<'l> {
	pub(crate) metadata_token: MetadataToken,
	pub(crate) name: InternedString<'l>,
	pub(crate) namespace: InternedString<'l>,
	pub(crate) methods: Vec<Method<'l>>,
}

impl TypePrivate for Interface<'_> {}

impl<'l> Type<'l> for Interface<'l> {
	fn write_as_blob(&self, stream: &mut dyn Write) -> std::io::Result<()> {
		let mut buffer = [0u8; 5];
		buffer[0] = 0x15;
		buffer[1..5].copy_from_slice(&self.metadata_token.raw().to_le_bytes());
		stream.write_all(&buffer)
	}
}

impl Display for Interface<'_> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		match self.namespace.is_empty() {
			true => write!(f, "{}", self.name),
			false => write!(f, "{}.{}", self.namespace, self.name),
		}
	}
}

pub trait DebuggableType<'l>: Type<'l> + Debug {}
impl<'l, T: Type<'l> + Debug> DebuggableType<'l> for T {}

mod private {
	pub type TypeDiscriminant = &'static str;

	#[inline(always)]
	pub fn get_type_discriminant<T: ?Sized>() -> TypeDiscriminant {
		// Terrible but it works
		std::any::type_name::<T>()
	}

	pub trait TypePrivate {}
}
