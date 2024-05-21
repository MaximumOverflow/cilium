use std::io::{Cursor, Error, ErrorKind, Read, Seek, SeekFrom};
use crate::raw::heaps::{StringHeap, StringIndex};
use std::mem::{MaybeUninit, size_of};
use std::slice::from_raw_parts_mut;
use std::iter::repeat_with;

#[inline]
pub(crate) unsafe fn read_pod_from_stream<T: Copy>(stream: &mut impl Read) -> std::io::Result<T> {
	let mut value = MaybeUninit::<T>::uninit();
	stream.read_exact(from_raw_parts_mut(
		value.as_mut_ptr() as *mut u8,
		size_of::<T>(),
	))?;
	Ok(value.assume_init())
}

#[inline]
pub(crate) fn read_bytes_slice_from_stream<'l>(
	stream: &mut Cursor<&'l [u8]>,
	count: usize,
) -> std::io::Result<&'l [u8]> {
	let start = stream.position() as usize;
	let range = start..start + count;
	if range.len() < count {
		return Err(Error::from(ErrorKind::UnexpectedEof));
	}
	stream.set_position(range.end as u64);
	Ok(&stream.get_ref()[range])
}

#[inline(never)]
pub(crate) fn read_string_from_stream_into<'a, const ROUND: usize>(
	stream: &mut Cursor<impl AsRef<[u8]>>,
	buffer: &'a mut [u8],
) -> std::io::Result<&'a str> {
	let position = stream.position();
	let max_len = stream.read(buffer)?;
	let str_end = buffer.iter().position(|v| *v == b'\0').unwrap_or(max_len);
	let str =
		std::str::from_utf8(&buffer[..str_end]).map_err(|_| Error::from(ErrorKind::InvalidData))?;
	let advance = round_to_multiple_of::<ROUND>(str_end + 1) as u64;
	stream.seek(SeekFrom::Start(position + advance))?;
	Ok(str)
}

pub trait FromByteStream
where
	Self: Sized,
{
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
	};
}

pub(crate) use impl_from_byte_stream;
use crate::schema::ReadError;

macro_rules! impl_from_le_byte_stream {
    ($($ty: ty),*) => {$(
		impl crate::utilities::FromByteStream for $ty {
			type Deps = ();
			#[inline]
			fn read(stream: &mut std::io::Cursor<&[u8]>, _: &Self::Deps) -> std::io::Result<Self> {
				let bytes = <[u8; size_of::<Self>()]>::read(stream, &())?;
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

impl FromByteStream for i8 {
	type Deps = ();
	#[inline]
	fn read(stream: &mut Cursor<&[u8]>, _: &Self::Deps) -> std::io::Result<Self> {
		let mut byte = 0u8;
		stream.read_exact(std::slice::from_mut(&mut byte))?;
		Ok(byte as i8)
	}
}

impl_from_le_byte_stream!(u16, u32, u64, i16, i32, i64, f32, f64);

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

pub(crate) fn enumerate_set_bits(mut value: u64) -> impl Iterator<Item = usize> {
	repeat_with(move || match value.trailing_zeros() {
		usize::BITS => usize::MAX,
		idx => {
			let mask = !(1u64 << idx as u64);
			value &= mask;
			idx as usize
		},
	})
	.take_while(|i| *i != usize::MAX)
}

#[inline]
pub(crate) fn get_string_from_heap(heap: &StringHeap, idx: StringIndex) -> Result<&str, ReadError> {
	heap.get(idx).ok_or_else(|| ReadError::InvalidStringToken(idx.into()))
}

// pub(crate) fn read_compressed_u32(stream: &mut Cursor<&[u8]>) -> Result<u32, Error> {
// 	let first = u8::read(stream, &())?;
// 	if first & 0x80 == 0 {
// 		return Ok(first as u32);
// 	}
//
// 	if first & 0x40 == 0 {
// 		let first = ((first & !0x80) as u32).overflowing_shl(8).0;
// 		let second = u8::read(stream, &())? as u32;
// 		return Ok(first | second);
// 	}
//
// 	let first = ((first & !0xc0) as u32).overflowing_shl(24).0;
// 	let second = (u8::read(stream, &())? as u32).overflowing_shl(16).0;
// 	let third = (u8::read(stream, &())? as u32).overflowing_shl(8).0;
// 	let fourth = u8::read(stream, &())? as u32;
//
// 	Ok(first | second | third | fourth)
// }

pub(crate) fn read_compressed_u32(stream: &mut Cursor<&[u8]>) -> Result<u32, Error> {
	let byte_0 = u8::read(stream, &())?;
	if byte_0 & 0x80 == 0 {
		Ok((byte_0 & 0x7F) as u32)
	} else if byte_0 & 0xC0 == 0x80 {
		let byte_1 = u8::read(stream, &())?;
		Ok((((byte_0 & 0x3F) as u32) << 8) + byte_1 as u32)
	} else if byte_0 & 0xE0 == 0xC0 {
		let byte_1 = u8::read(stream, &())?;
		let byte_2 = u8::read(stream, &())?;
		Ok((((byte_0 & 0x3F) as u32) << 16) + ((byte_1 as u32) << 8) + byte_2 as u32)
	} else {
		return Err(Error::new(ErrorKind::InvalidData, format!("Invalid compressed u32 header {:#X}", byte_0)));
	}
}
