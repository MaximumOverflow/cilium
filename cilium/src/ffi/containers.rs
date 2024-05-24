use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

#[repr(transparent)]
pub struct Box<T> {
	data: *mut T,
}

impl<T> From<T> for Box<T> {
	fn from(value: T) -> Self {
		Self { data: std::boxed::Box::leak(std::boxed::Box::from(value)) }
	}
}

impl<T> Drop for Box<T> {
	fn drop(&mut self) {
		unsafe { drop(std::boxed::Box::from_raw(self.data)) }
	}
}

impl<T> Deref for Box<T> {
	type Target = T;
	fn deref(&self) -> &Self::Target {
		unsafe { &*self.data }
	}
}

impl<T> DerefMut for Box<T> {
	fn deref_mut(&mut self) -> &mut Self::Target {
		unsafe { &mut *self.data }
	}
}

impl<T: Debug> Debug for Box<T> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		Debug::fmt(&**self, f)
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Slice<'l, T> {
	data: *const T,
	len: usize,
	ph: PhantomData<&'l T>,
}

impl<'l, T> Slice<'l, T> {
	pub fn as_ref(&self) -> &'l [T] {
		unsafe { std::slice::from_raw_parts(self.data, self.len) }
	}
}

impl<'l, T> From<&'l [T]> for Slice<'l, T> {
	fn from(value: &'l [T]) -> Self {
		Self {
			data: value.as_ptr(),
			len: value.len(),
			ph: PhantomData,
		}
	}
}

impl<'l, T, const S: usize> From<&'l [T; S]> for Slice<'l, T> {
	fn from(value: &'l [T; S]) -> Self {
		Self {
			data: value.as_ptr(),
			len: value.len(),
			ph: PhantomData,
		}
	}
}

impl<'l, T> Deref for Slice<'l, T> {
	type Target = [T];
	fn deref(&self) -> &'l Self::Target {
		self.as_ref()
	}
}

impl<T: Eq> Eq for Slice<'_, T> {}
impl<T: PartialEq> PartialEq for Slice<'_, T> {
	fn eq(&self, other: &Self) -> bool {
		(**self).eq(&**other)
	}
}

impl<T: Debug> Debug for Slice<'_, T> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		(*self).deref().fmt(f)
	}
}

#[repr(C)]
pub struct BoxSlice<T> {
	data: *mut T,
	len: usize,
}

impl<T> Deref for BoxSlice<T> {
	type Target = [T];
	fn deref(&self) -> &Self::Target {
		unsafe { std::slice::from_raw_parts(self.data, self.len) }
	}
}

impl<T> DerefMut for BoxSlice<T> {
	fn deref_mut(&mut self) -> &mut Self::Target {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.len) }
	}
}

impl<T> From<Vec<T>> for BoxSlice<T> {
	fn from(value: Vec<T>) -> Self {
		Self::from(value.into_boxed_slice())
	}
}

impl<T> From<std::boxed::Box<[T]>> for BoxSlice<T> {
	fn from(value: std::boxed::Box<[T]>) -> Self {
		Self {
			len: value.len(),
			data: std::boxed::Box::leak(value).as_mut_ptr(),
		}
	}
}

impl<T> Drop for BoxSlice<T> {
	fn drop(&mut self) {
		unsafe { drop(std::boxed::Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.len))) }
	}
}

impl<T: Clone> Clone for BoxSlice<T> {
	fn clone(&self) -> Self {
		Self::from(std::boxed::Box::from_iter(self.iter().cloned()))
	}
}

impl<T: Eq> Eq for BoxSlice<T> {}
impl<T: PartialEq> PartialEq for BoxSlice<T> {
	fn eq(&self, other: &Self) -> bool {
		(**self).eq(&**other)
	}
}

impl<T: Debug> Debug for BoxSlice<T> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		(*self).deref().fmt(f)
	}
}
