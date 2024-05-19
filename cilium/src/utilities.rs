use std::borrow::Borrow;
use std::io::{Cursor, Error, ErrorKind, Read, Seek, SeekFrom};
use std::iter::repeat_with;
use std::mem::{MaybeUninit, size_of};
use std::slice::from_raw_parts_mut;
use std::sync::Arc;
use owning_ref::{ArcRef, OwningRef, StringRef};

#[inline]
pub(crate) unsafe fn read_pod_from_stream<T: Copy>(stream: &mut impl Read) -> std::io::Result<T> {
	let mut value = MaybeUninit::<T>::uninit();
	stream.read_exact(from_raw_parts_mut(value.as_mut_ptr() as *mut u8, size_of::<T>()))?;
	Ok(value.assume_init())
}

#[inline]
pub(crate) fn read_bytes_slice_from_stream(stream: &mut Cursor<impl AsRef<[u8]>>, count: usize) -> std::io::Result<&[u8]> {
	let start = stream.position() as usize;
	let range = start..start + count;
	if range.len() < count {
		return Err(Error::from(ErrorKind::UnexpectedEof));
	}
	stream.set_position(range.end as u64);
	Ok(&stream.get_ref().as_ref()[range])
}

#[inline(never)]
pub(crate) fn read_string_from_stream_into<'a, const ROUND: usize>(stream: &mut Cursor<impl AsRef<[u8]>>, buffer: &'a mut [u8]) -> std::io::Result<&'a str> {
	let position = stream.position();
	let max_len = stream.read(buffer)?;
	let str_end = buffer.iter().position(|v| *v == b'\0').unwrap_or(max_len);
	let str = std::str::from_utf8(&buffer[..str_end]).map_err(|_| Error::from(ErrorKind::InvalidData))?;
	let advance = round_to_multiple_of::<ROUND>(str_end + 1) as u64;
	stream.seek(SeekFrom::Start(position + advance))?;
	Ok(str)
}

pub trait FromByteStream where Self: Sized {
	type Deps;
	fn read(stream: &mut Cursor<&[u8]>, deps: &Self::Deps) -> std::io::Result<Self>;
}

// TODO handle big endian architectures
macro_rules! impl_from_byte_stream {
	($ty: ty) => {
		impl crate::utilities::FromByteStream for $ty {
			type Deps = ();
			#[inline]
			fn read(stream: &mut std::io::Cursor<&[u8]>, _: &Self::Deps) -> std::io::Result<Self> {
				unsafe { crate::utilities::read_pod_from_stream(stream) }
			}
		}
	};

	($ty: ty, $magic: literal) => {
		impl crate::utilities::FromByteStream for $ty {
			type Deps = ();
			#[inline]
			fn read(stream: &mut std::io::Cursor<&[u8]>, _: &Self::Deps) -> std::io::Result<Self> {
				let value = unsafe { crate::utilities::read_pod_from_stream::<$ty>(stream)? };
				match value.magic == $magic {
					true => Ok(value),
					false => Err(std::io::Error::from(std::io::ErrorKind::InvalidData)),
				}
			}
		}
	}
}

pub(crate) use impl_from_byte_stream;

macro_rules! impl_from_le_byte_stream {
    ($($ty: ty),*) => {$(
		impl crate::utilities::FromByteStream for $ty {
			type Deps = ();
			#[inline]
			fn read(stream: &mut std::io::Cursor<&[u8]>, _: &Self::Deps) -> std::io::Result<Self> {
				let mut bytes = <[u8; size_of::<Self>()]>::read(stream, &())?;
				Ok(Self::from_le_bytes(bytes))
			}
		}
	)*};
}

impl FromByteStream for u8 {
	type Deps = ();
	#[inline]
	fn read(stream: &mut Cursor<&[u8]>, _: &Self::Deps) -> std::io::Result<Self> {
		let mut byte = 0u8;
		stream.read_exact(std::slice::from_mut(&mut byte))?;
		Ok(byte)
	}
}

impl_from_le_byte_stream!(u16, u32, u64);

impl<const SIZE: usize> FromByteStream for [u8; SIZE] {
	type Deps = ();
	#[inline]
	fn read(stream: &mut Cursor<&[u8]>, _: &Self::Deps) -> std::io::Result<Self> {
		let mut bytes = [0u8; SIZE];
		stream.read_exact(&mut bytes)?;
		Ok(bytes)
	}
}

#[inline]
pub(crate) const fn round_to_multiple_of<const MULTIPLE: usize>(value: usize) -> usize {
	((value + (MULTIPLE - 1)) / MULTIPLE) * MULTIPLE
}

pub(crate) fn enumerate_set_bits(mut value: u64) -> impl Iterator<Item=usize> {
	repeat_with(move || {
		match value.trailing_zeros() {
			usize::BITS => usize::MAX,
			idx => {
				let mask = !(1u64 << idx as u64);
				value &= mask;
				idx as usize
			},
		}
	}).take_while(|i| {
		*i != usize::MAX
	})
}
