use std::mem::size_of;

#[inline]
pub(crate) fn read_raw<T: Copy>(bytes: &[u8]) -> Result<T, &'static str> {
	if bytes.len() != size_of::<T>() {
		return Err("Invalid buffer size");
	}
	unsafe { Ok(std::ptr::read_unaligned(bytes.as_ptr() as *const T)) }
}

macro_rules! impl_from_bytes {
    ($ty: ty) => {
		impl TryFrom<&[u8]> for $ty {
			type Error = &'static str;
			#[inline]
			fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
				crate::utilities::read_raw(buffer)
			}
		}
	};

	($ty: ty, $magic: literal) => {
		impl TryFrom<&[u8]> for $ty {
			type Error = &'static str;
			#[inline]
			fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
				let value = crate::utilities::read_raw::<$ty>(buffer)?;
				match value.magic == $magic {
					true => Ok(value),
					false => Err("Magic value does not match"),
				}
			}
		}
	};
}

pub(crate) use impl_from_bytes;
