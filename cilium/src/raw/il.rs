use std::fmt::{Debug, Formatter};
use std::io::{Cursor, Error, ErrorKind, Read};
use std::io::Result;
use std::sync::Arc;

use bitflags::bitflags;
use derivative::Derivative;

use crate::raw::FromByteStream;
use crate::raw::heaps::BlobHeap;
use crate::raw::heaps::table::StandAloneSigTable;
use crate::raw::indices::coded_index::TypeDefOrRef;
use crate::raw::indices::metadata_token::{MetadataToken, StandAloneSig};
use crate::raw::indices::sizes::IndexSizes;
use crate::utilities::{impl_from_byte_stream, read_bytes_slice_from_stream, read_compressed_u32};

macro_rules! debug_opcode {
	($name: ident, $f: expr, $self: expr, $ident: ident) => {
		if $name::$ident == *$self {
			return write!($f, "OpCode::{}", stringify!($ident));
		}
	};
	($name: ident, $f: expr, $self: expr, $ident: ident ($ty: ty)) => {
		if let $name::$ident(v) = $self {
			return write!($f, "OpCode::{}({:#X?})", stringify!($ident), v);
		}
	};
}

macro_rules! define_opcodes {
    (
		enum $name: ident  $(<$lifetime: lifetime>)? {
			$(
				$(#[$attr:meta])*
				$ident: ident $(($ty: ty))? = $discriminant: literal
			),*
		}
	) => {
		#[repr(u8)]
		#[allow(non_camel_case_types)]
		#[derive(Copy, Clone, PartialEq)]
		pub enum $name $(<$lifetime>)? {
			$(
				$(#[$attr])*
				$ident $(($ty))? = $discriminant
			),*
		}

		impl$(<$lifetime>)? $name$(<$lifetime>)? {
			pub fn read(stream: &mut Cursor<& $($lifetime)? [u8]>, _: &()) -> Result<Self> {
				let mut discriminant = 0u8;
				stream.read_exact(std::slice::from_mut(&mut discriminant))?;

				match discriminant {
					$($discriminant => Ok($name::$ident $((<$ty>::read(stream, &())?))?),)*
					_ => unimplemented!("Unimplemented OpCode {:#X?}", discriminant),
				}
			}
		}

		impl $(<$lifetime>)? Debug for $name $(<$lifetime>)? {
			fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
				$(debug_opcode! { $name, f, self, $ident $(($ty))? })*
				Ok(())
			}
		}
	};
}

define_opcodes! {
	enum OpCode<'l> {
		/// Do nothing (No operation).
		nop = 0x00,
		/// Inform a debugger that a breakpoint has been reached.
		dbg_break = 0x01,
		/// Load argument 0 onto the stack.
		ldarg_0 = 0x02,
		/// Load argument 1 onto the stack.
		ldarg_1 = 0x03,
		/// Load argument 2 onto the stack.
		ldarg_2 = 0x04,
		/// Load argument 3 onto the stack.
		ldarg_3 = 0x05,
		/// Load local variable 0 onto stack.
		ldloc_0 = 0x06,
		/// Load local variable 1 onto stack.
		ldloc_1 = 0x07,
		/// Load local variable 2 onto stack.
		ldloc_2 = 0x08,
		/// Load local variable 3 onto stack.
		ldloc_3 = 0x09,
		/// Pop a value from stack into local variable 0.
		stloc_0 = 0x0A,
		/// Pop a value from stack into local variable 1.
		stloc_1 = 0x0B,
		/// Pop a value from stack into local variable 2.
		stloc_2 = 0x0C,
		/// Pop a value from stack into local variable 3.
		stloc_3 = 0x0D,
		/// Load argument numbered num onto the stack, short form.
		ldarg_s(u8) = 0x0E,
		/// Fetch the address of argument argNum, short form.
		ldarga_s(u8) = 0x0F,
		/// Store value to the argument numbered num, short form.
		starg_s(u8) = 0x10,
		/// Load local variable of index indx onto stack, short form.
		ldloc_s(u8) = 0x11,
		/// Load address of local variable with index indx, short form.
		ldloca_s(u8) = 0x12,
		/// Pop a value from stack into local variable indx, short form.
		stloc_s(u8) = 0x13,
		/// Push a null reference on the stack.
		ldnull = 0x14,
		/// Push -1 onto the stack as int32.
		ldc_i4_m1 = 0x15,
		/// Push 0 onto the stack as int32.
		ldc_i4_0 = 0x16,
		/// Push 1 onto the stack as int32.
		ldc_i4_1 = 0x17,
		/// Push 2 onto the stack as int32.
		ldc_i4_2 = 0x18,
		/// Push 3 onto the stack as int32.
		ldc_i4_3 = 0x19,
		/// Push 4 onto the stack as int32.
		ldc_i4_4 = 0x1A,
		/// Push 5 onto the stack as int32.
		ldc_i4_5 = 0x1B,
		/// Push 6 onto the stack as int32.
		ldc_i4_6 = 0x1C,
		/// Push 7 onto the stack as int32.
		ldc_i4_7 = 0x1D,
		/// Push 8 onto the stack as int32.
		ldc_i4_8 = 0x1E,
		/// Push num onto the stack as int32, short form.
		ldc_i4_s(u8) = 0x1F,
		/// Push num of type int32 onto the stack as int32.
		ldc_i4(i32) = 0x20,
		/// Push num of type int64 onto the stack as int64.
		ldc_i8(i64) = 0x21,
		/// Push num of type float32 onto the stack as F.
		ldc_r4(f32) = 0x22,
		/// Push num of type float64 onto the stack as F.
		ldc_r8(f64) = 0x23,
		/// Duplicate the value on the top of the stack.
		dup = 0x25,
		/// Pop value from the stack.
		pop = 0x26,
		/// Exit current method and jump to the specified method.
		jmp(MetadataToken) = 0x27,
		/// Call method described by method.
		call(MetadataToken) = 0x28,
		/// Call method indicated on the stack with arguments described by callsitedescr.
		calli(MetadataToken) = 0x29,
		/// Return from method, possibly with a value.
		ret = 0x2A,
		/// Branch to target, short form.
		br_s(i8) = 0x2B,
		/// Branch to target if value is zero (false), short form.
		brfalse_s(i8) = 0x2C,
		/// Branch to target if value is non-zero (true), short form.
		brtrue_s(i8) = 0x2D,
		/// Branch to target if equal, short form.
		beq_s(i8) = 0x2E,
		/// Branch to target if greater than or equal to, short form.
		bge_s(i8) = 0x2F,
		/// Branch to target if greater than, short form.
		bgt_s(i8) = 0x30,
		/// Branch to target if less than or equal to, short form.
		ble_s(i8) = 0x31,
		/// Branch to target if less than, short form.
		blt_s(i8) = 0x32,
		/// Branch to target if unequal or unordered, short form.
		bne_un_s(i8) = 0x33,
		/// Branch to target if greater than or equal to (unsigned or unordered), short form.
		bge_un_s(i8) = 0x34,
		/// Branch to target if greater than (unsigned or unordered), short form.
		bgt_un_s(i8) = 0x35,
		/// Branch to target if less than or equal to (unsigned or unordered), short form.
		ble_un_s(i8) = 0x36,
		/// Branch to target if less than (unsigned or unordered), short form.
		blt_un_s(i8) = 0x37,
		/// Branch to target.
		br(i32) = 0x38,
		/// Branch to target if value is zero (false).
		brfalse(i32) = 0x39,
		/// Branch to target if value is non-zero (true).
		brtrue(i32) = 0x3A,
		/// Branch to target if equal.
		beq(i32) = 0x3B,
		/// Branch to target if greater than or equal to.
		bge(i32) = 0x3C,
		/// Branch to target if greater than.
		bgt(i32) = 0x3D,
		/// Branch to target if less than or equal to.
		ble(i32) = 0x3E,
		/// Branch to target if less than.
		blt(i32) = 0x3F,
		/// Branch to target if unequal or unordered.
		bne_un(i32) = 0x40,
		/// Branch to target if greater than or equal to (unsigned or unordered).
		bge_un(i32) = 0x41,
		/// Branch to target if greater than (unsigned or unordered).
		bgt_un(i32) = 0x42,
		/// Branch to target if less than or equal to (unsigned or unordered).
		ble_un(i32) = 0x43,
		/// Branch to target if less than (unsigned or unordered).
		blt_un(i32) = 0x44,
		/// Jump to one of n values.
		switch(SwitchTable<'l>) = 0x45,
		/// Indirect load value of type int8 as int32 on the stack.
		ldind_i1 = 0x46,
		/// Indirect load value of type unsigned int8 as int32 on the stack.
		ldind_u1 = 0x47,
		/// Indirect load value of type int16 as int32 on the stack.
		ldind_i2 = 0x48,
		/// Indirect load value of type unsigned int16 as int32 on the stack.
		ldind_u2 = 0x49,
		/// Indirect load value of type int32 as int32 on the stack.
		ldind_i4 = 0x4A,
		/// Indirect load value of type unsigned int32 as int32 on the stack.
		ldind_u4 = 0x4B,
		/// Indirect load value of type int64 as int64 on the stack.
		ldind_i8 = 0x4C,
		/// Indirect load value of type native int as native int on the stack.
		ldind_i = 0x4D,
		/// Indirect load value of type float32 as F on the stack.
		ldind_r4 = 0x4E,
		/// Indirect load value of type float64 as F on the stack.
		ldind_r8 = 0x4F,
		/// Indirect load value of type object ref as O on the stack.
		ldind_ref = 0x50,
		/// Store value of type object ref (type O) into memory at address.
		stind_ref = 0x51,
		/// Store value of type int8 into memory at address.
		stind_i1 = 0x52,
		/// Store value of type int16 into memory at address.
		stind_i2 = 0x53,
		/// Store value of type int32 into memory at address.
		stind_i4 = 0x54,
		/// Store value of type int64 into memory at address.
		stind_i8 = 0x55,
		/// Store value of type float32 into memory at address.
		stind_r4 = 0x56,
		/// Store value of type float64 into memory at address.
		stind_r8 = 0x57,
		/// Add two values, returning a new value.
		add = 0x58,
		/// Subtract value2 from value1, returning a new value.
		sub = 0x59,
		/// Multiply values.
		mul = 0x5A,
		/// Divide two values to return a quotient or floating-point result.
		div = 0x5B,
		/// Divide two values, unsigned, returning a quotient.
		div_un = 0x5C,
		/// Remainder when dividing one value by another.
		rem = 0x5D,
		/// Remainder when dividing one unsigned value by another.
		rem_un = 0x5E,
		/// Bitwise AND of two integral values, returns an integral value.
		and = 0x5F,
		/// Bitwise OR of two integer values, returns an integer.
		or = 0x60,
		/// Bitwise XOR of integer values, returns an integer.
		xor = 0x61,
		/// Shift an integer left (shifting in zeros), return an integer.
		shl = 0x62,
		/// Shift an integer right (shift in sign), return an integer.
		shr = 0x63,
		/// Shift an integer right (shift in zero), return an integer.
		shr_un = 0x64,
		/// Negate value.
		neg = 0x65,
		/// Bitwise complement.
		not = 0x66,
		/// Convert to int8, pushing int32 on stack.
		conv_i1 = 0x67,
		/// Convert to int16, pushing int32 on stack.
		conv_i2 = 0x68,
		/// Convert to int32, pushing int32 on stack.
		conv_i4 = 0x69,
		/// Convert to int64, pushing int64 on stack.
		conv_i8 = 0x6A,
		/// Convert to float32, pushing F on stack.
		conv_r4 = 0x6B,
		/// Convert to float64, pushing F on stack.
		conv_r8 = 0x6C,
		/// Convert to unsigned int32, pushing int32 on stack.
		conv_u4 = 0x6D,
		/// Convert to unsigned int64, pushing int64 on stack.
		conv_u8 = 0x6E,
		/// Call a method associated with an object.
		callvirt(MetadataToken) = 0x6F,
		/// Copy a value type from src to dest.
		cpobj(MetadataToken) = 0x70,
		/// Copy the value stored at address src to the stack.
		ldobj(MetadataToken) = 0x71,
		/// Push a string object for the literal string.
		ldstr(MetadataToken) = 0x72,
		/// Allocate an uninitialized object or value type and call ctor.
		newobj(MetadataToken) = 0x73,
		/// Cast obj to class.
		castclass(MetadataToken) = 0x74,
		/// Test if obj is an instance of class, returning null or an instance of that class or interface.
		isinst(MetadataToken) = 0x75,
		/// Convert unsigned integer to floating-point, pushing F on stack.
		conv_r_un = 0x76,
		/// Extract a value-type from obj, its boxed representation, and push a controlled-mutability managed pointer to it to the top of the stack.
		unbox(MetadataToken) = 0x79,
		/// Throw an exception.
		throw = 0x7A,
		/// Push the value of field of object (or value type) obj, onto the stack.
		ldfld(MetadataToken) = 0x7B,
		/// Push the address of field of object obj on the stack.
		ldflda(MetadataToken) = 0x7C,
		/// Replace the value of field of the object obj with value.
		stfld(MetadataToken) = 0x7D,
		/// Push the value of the static field on the stack.
		ldsfld(MetadataToken) = 0x7E,
		/// Push the address of the static field, field, on the stack.
		ldsflda(MetadataToken) = 0x7F,
		/// Replace the value of the static field with val.
		stsfld(MetadataToken) = 0x80,
		/// Store a value of type typeTok at an address.
		stobj(MetadataToken) = 0x81,
		/// Convert unsigned to an int8 (on the stack as int32) and throw an exception on overflow.
		conv_ovf_i1_un = 0x82,
		/// Convert unsigned to an int16 (on the stack as int32) and throw an exception on overflow.
		conv_ovf_i2_un = 0x83,
		/// Convert unsigned to an int32 (on the stack as int32) and throw an exception on overflow.
		conv_ovf_i4_un = 0x84,
		/// Convert unsigned to an int64 (on the stack as int64) and throw an exception on overflow.
		conv_ovf_i8_un = 0x85,
		/// Convert unsigned to an unsigned int8 (on the stack as int32) and throw an exception on overflow.
		conv_ovf_u1_un = 0x86,
		/// Convert unsigned to an unsigned int16 (on the stack as int32) and throw an exception on overflow.
		conv_ovf_u2_un = 0x87,
		/// Convert unsigned to an unsigned int32 (on the stack as int32) and throw an exception on overflow.
		conv_ovf_u4_un = 0x88,
		/// Convert unsigned to an unsigned int64 (on the stack as int64) and throw an exception on overflow.
		conv_ovf_u8_un = 0x89,
		/// Convert unsigned to a native int (on the stack as native int) and throw an exception on overflow.
		conv_ovf_i_un = 0x8A,
		/// Convert unsigned to a native unsigned int (on the stack as native int) and throw an exception on overflow.
		conv_ovf_u_un = 0x8B,
		/// Convert a boxable value to its boxed form.
		box_val(MetadataToken) = 0x8C,
		/// Create a new array with elements of type etype.
		newarr(MetadataToken) = 0x8D,
		/// Push the length (of type native unsigned int) of array on the stack.
		ldlen = 0x8E,
		/// Load the address of element at index onto the top of the stack.
		ldelema(MetadataToken) = 0x8F,
		/// Load the element with type int8 at index onto the top of the stack as an int32.
		ldelem_i1 = 0x90,
		/// Load the element with type unsigned int8 at index onto the top of the stack as an int32.
		ldelem_u1 = 0x91,
		/// Load the element with type int16 at index onto the top of the stack as an int32.
		ldelem_i2 = 0x92,
		/// Load the element with type unsigned int16 at index onto the top of the stack as an int32.
		ldelem_u2 = 0x93,
		/// Load the element with type int32 at index onto the top of the stack as an int32.
		ldelem_i4 = 0x94,
		/// Load the element with type unsigned int32 at index onto the top of the stack as an int32.
		ldelem_u4 = 0x95,
		/// Load the element with type int64 at index onto the top of the stack as an int64.
		ldelem_i8 = 0x96,
		/// Load the element with type native int at index onto the top of the stack as a native int.
		ldelem_i = 0x97,
		/// Load the element with type float32 at index onto the top of the stack as an F.
		ldelem_r4 = 0x98,
		/// Load the element with type float64 at index onto the top of the stack as an F.
		ldelem_r8 = 0x99,
		/// Load the element at index onto the top of the stack as an O. The type of the O is the same as the element type of the array pushed on the CIL stack.
		ldelem_ref = 0x9A,
		/// Replace array element at index with the native int value on the stack.
		stelem_i = 0x9B,
		/// Replace array element at index with the int8 value on the stack.
		stelem_i1 = 0x9C,
		/// Replace array element at index with the int16 value on the stack.
		stelem_i2 = 0x9D,
		/// Replace array element at index with the int32 value on the stack.
		stelem_i4 = 0x9E,
		/// Replace array element at index with the int64 value on the stack.
		stelem_i8 = 0x9F,
		/// Replace array element at index with the float32 value on the stack.
		stelem_r4 = 0xA0,
		/// Replace array element at index with the float64 value on the stack.
		stelem_r8 = 0xA1,
		/// Replace array element at index with the ref value on the stack.
		stelem_ref = 0xA2,
		/// Load the element at index onto the top of the stack.
		ldelem(MetadataToken) = 0xA3,
		/// Replace array element at index with the value on the stack.
		stelem(MetadataToken) = 0xA4,
		/// Extract a value-type from obj, its boxed representation, and copy to the top of the stack.
		unbox_any(MetadataToken) = 0xA5,
		/// Convert to an int8 (on the stack as int32) and throw an exception on overflow.
		conv_ovf_i1 = 0xB3,
		/// Convert to an unsigned int8 (on the stack as int32) and throw an exception on overflow.
		conv_ovf_u1 = 0xB4,
		/// Convert to an int16 (on the stack as int32) and throw an exception on overflow.
		conv_ovf_i2 = 0xB5,
		/// Convert to an unsigned int16 (on the stack as int32) and throw an exception on overflow.
		conv_ovf_u2 = 0xB6,
		/// Convert to an int32 (on the stack as int32) and throw an exception on overflow.
		conv_ovf_i4 = 0xB7,
		/// Convert to an unsigned int32 (on the stack as int32) and throw an exception on overflow.
		conv_ovf_u4 = 0xB8,
		/// Convert to an int64 (on the stack as int64) and throw an exception on overflow.
		conv_ovf_i8 = 0xB9,
		/// Convert to an unsigned int64 (on the stack as int64) and throw an exception on overflow.
		conv_ovf_u8 = 0xBA,
		/// Push the address stored in a typed reference.
		refanyval(MetadataToken) = 0xC2,
		/// Throw ArithmeticException if value is not a finite number.
		ckfinite = 0xC3,
		/// Push a typed reference to ptr of type class onto the stack.
		mkrefany(MetadataToken) = 0xC6,
		/// Convert metadata token to its runtime representation.
		ldtoken(MetadataToken) = 0xD0,
		/// Convert to unsigned int16, pushing int32 on stack.
		conv_u2 = 0xD1,
		/// Convert to unsigned int8, pushing int32 on stack.
		conv_u1 = 0xD2,
		/// Convert to native int, pushing native int on stack.
		conv_i = 0xD3,
		/// Convert to a native int (on the stack as native int) and throw an exception on overflow.
		conv_ovf_i = 0xD4,
		/// Convert to a native unsigned int (on the stack as native int) and throw an exception on overflow.
		conv_ovf_u = 0xD5,
		/// Add signed integer values with overflow check.
		add_ovf = 0xD6,
		/// Add unsigned integer values with overflow check.
		add_ovf_un = 0xD7,
		/// Multiply signed integer values. Signed result shall fit in same size.
		mul_ovf = 0xD8,
		/// Multiply unsigned integer values. Unsigned result shall fit in same size.
		mul_ovf_un = 0xD9,
		/// Subtract native int from a native int. Signed result shall fit in same size.
		sub_ovf = 0xDA,
		/// Subtract native unsigned int from a native unsigned int. Unsigned result shall fit in same size.
		sub_ovf_un = 0xDB,
		/// End fault clause of an exception block.
		endfinally = 0xDC,
		/// End finally clause of an exception block.
		leave(i32) = 0xDD,
		/// Exit a protected region of code.
		leave_s(i8) = 0xDE,
		/// Exit a protected region of code, short form.
		stind_i = 0xDF,
		/// Store value of type native int into memory at address.
		conv_u = 0xE0,
		compound(CompoundOpCode) = 0xFE
	}
}

define_opcodes! {
	enum CompoundOpCode {
		/// Return argument list handle for the current method.
		arglist = 0x00,
		/// Push 1 (of type int32) if value1 equals value2, else push 0.
		ceq = 0x01,
		/// Push 1 (of type int32) if value1 greater that value2, else push 0.
		cgt = 0x02,
		/// Push 1 (of type int32) if value1 greater that value2, unsigned or unordered, else push 0.
		cgt_un = 0x03,
		/// Push 1 (of type int32) if value1 lower than value2, else push 0.
		clt = 0x04,
		/// Push 1 (of type int32) if value1 lower than value2, unsigned or unordered, else push 0.
		clt_un = 0x05,
		/// Push a pointer to a method referenced by method, on the stack.
		ldftn(MetadataToken) = 0x06,
		/// Push address of virtual method on the stack.
		ldvirtftn(MetadataToken) = 0x07,
		/// Load argument numbered num onto the stack.
		ldarg(u16) = 0x09,
		/// Fetch the address of argument argNum.
		ldarga(u16) = 0x0A,
		/// Store value to the argument numbered num.
		starg(u16) = 0x0B,
		/// Load local variable of index indx onto stack.
		ldloc(u16) = 0x0C,
		/// Load address of local variable with index indx.
		ldloca(u16) = 0x0D,
		/// Pop a value from stack into local variable indx.
		stloc(u16) = 0x0E,
		/// Allocate space from the local memory pool.
		localloc = 0x0F,
		/// End an exception handling filter clause.
		endfilter = 0x11,
		/// Subsequent pointer instruction might be unaligned.
		unaligned = 0x12,
		/// Subsequent pointer reference is volatile.
		volatile = 0x13,
		/// Subsequent call terminates current method.
		tail = 0x14,
		/// Initialize the value at address dest.
		initobj(MetadataToken) = 0x15,
		/// Call a virtual method on a type constrained to be type T.
		constrained(MetadataToken) = 0x16,
		/// Copy data from memory to memory.
		cpblk = 0x17,
		/// Set all bytes in a block of memory to a given byte value.
		initblk = 0x18,
		/// The specified fault check(s) normally performed as part of the execution of the subsequent instruction can/shall be skipped.
		no_chk(SkipFaultCheckFlags) = 0x19,
		/// Rethrow the current exception.
		rethrow = 0x1A,
		/// Push the size, in bytes, of a type as an unsigned int32.
		sizeof(MetadataToken) = 0x1C,
		/// Push the type token stored in a typed reference.
		refanytype = 0x1D,
		/// Specify that the subsequent array address operation performs no type check at runtime, and that it returns a controlled-mutability managed pointer.
		readonly = 0x1E
	}
}

bitflags! {
	#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct SkipFaultCheckFlags: u8 {
		const TYPE_CHECK = 0x1;
		const RANGE_CHECK = 0x2;
		const NULL_CHECK = 0x4;
	}
}

impl_from_byte_stream!(SkipFaultCheckFlags);

#[derive(Copy, Clone, PartialEq, Hash)]
pub struct SwitchTable<'l>(&'l [u8]);

impl Debug for SwitchTable<'_> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		let mut dbg = f.debug_list();
		for variant in self.variants() {
			dbg.entry(&variant);
		}
		dbg.finish()
	}
}

impl<'l> SwitchTable<'l> {
	pub fn read(stream: &mut Cursor<&'l [u8]>, _: &()) -> Result<Self> {
		let len = u32::read(stream, &())?;
		let data = read_bytes_slice_from_stream(stream, len as usize * 4)?;
		Ok(Self(data))
	}

	pub fn len(&self) -> usize {
		self.0.len() / 4
	}

	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	#[inline]
	pub fn variants(&self) -> impl Iterator<Item=i32> + '_ {
		(0..self.len()).map(move |i| {
			let slice = &self.0[i * 4..(i + 1) * 4];
			i32::from_le_bytes(slice.try_into().unwrap())
		})
	}
}

pub struct OpCodeIterator<'l> {
	cursor: Cursor<&'l [u8]>
}

impl<'l> OpCodeIterator<'l> {
	pub fn new(bytes: &'l [u8]) -> Self {
		Self { cursor: Cursor::new(bytes) }
	}
}

impl<'l> Iterator for OpCodeIterator<'l> {
	type Item = (u64, Result<OpCode<'l>>);
	fn next(&mut self) -> Option<Self::Item> {
		let position = self.cursor.position();
		match position == self.cursor.get_ref().len() as u64 {
			true => None,
			false => Some((position, OpCode::read(&mut self.cursor, &()))),
		}
	}
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct MethodBody<'l> {
	pub max_stack_size: u16,
	pub init_locals: bool,
	pub locals: Vec<TypeSignature<'l>>,
	#[derivative(Debug(format_with="debug_opcodes"))]
	pub code: &'l [u8],
}

impl<'l> MethodBody<'l> {
	pub fn read(
		stream: &mut Cursor<&'l [u8]>,
		blob_heap: &'l BlobHeap,
		signatures: &StandAloneSigTable,
		index_sizes: &Arc<IndexSizes>,
	) -> Result<Self> {
		let header = u8::read(stream, &())?;
		match header & 3 {
			2 => {
				let code_size = (header >> 2) as usize;
				let code = read_bytes_slice_from_stream(stream, code_size)?;
				Ok(Self { code, max_stack_size: 8, init_locals: false, locals: vec![] })
			}
			3 => {
				stream.set_position(stream.position() - 1);
				let flags = u16::read(stream, &())?;
				let max_stack_size = u16::read(stream, &())?;
				let code_size = u32::read(stream, &())?;
				let init_locals = flags & 0x10 != 0;

				let mut locals = vec![];
				let local_var_token = u32::read(stream, &())?;
				if local_var_token != 0 {
					let Ok(local_var_token) = MetadataToken::try_from(local_var_token) else {
						return Err(Error::new(ErrorKind::InvalidData, "Invalid metadata token"));
					};
					let Ok(StandAloneSig(local_var_token)) = local_var_token.try_into() else {
						return Err(Error::new(ErrorKind::InvalidData, "Invalid metadata token"));
					};
					let sig = signatures.get(local_var_token - 1).unwrap().signature;
					let Some(sig) = blob_heap.get(sig) else {
						return Err(Error::new(ErrorKind::InvalidData, "Invalid blob index"));
					};

					let mut stream = Cursor::new(sig);
					if u8::read(&mut stream, &())? != 0x07 {
						return Err(Error::new(ErrorKind::InvalidData, "Blob is not a local signature"));
					}

					let count = read_compressed_u32(&mut stream)? as usize;

					locals.reserve_exact(count);
					for _ in 0..count {
						let signature = TypeSignature::read(&mut stream, index_sizes)?;
						locals.push(signature);
					}
				}


				let code = read_bytes_slice_from_stream(stream, code_size as usize)?;

				// TODO read section

				Ok(Self { max_stack_size, init_locals, code, locals })
			},
			_ => return Err(Error::new(ErrorKind::InvalidData, "Invalid method header")),
		}
	}
}

pub(crate) fn debug_opcodes(bytes: &[u8], fmt: &mut Formatter) -> std::result::Result<(), std::fmt::Error> {
	let mut dbg = fmt.debug_list();
	for (i, opcode) in OpCodeIterator::new(bytes) {
		let opcode = opcode.unwrap();
		dbg.entry(&format_args!("IL_{i:08X}\t{opcode:X?}"));
	}
	dbg.finish()
}

#[derive(Clone)]
pub struct TypeSignature<'l>(&'l [u8], Arc<IndexSizes>);

impl Debug for TypeSignature<'_> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		let mut stream = Cursor::new(self.0);
		let sig = TypeSignatureTag::read(&mut stream, &self.1).unwrap();
		Debug::fmt(&sig, f)
	}
}

impl<'l> TypeSignature<'l> {
	pub fn read(stream: &mut Cursor<&'l [u8]>, index_sizes: &Arc<IndexSizes>) -> Result<Self> {
		let start = stream.position() as usize;
		let _ = TypeSignatureTag::read(stream, index_sizes)?;
		Ok(Self(&stream.get_ref()[start..stream.position() as usize], index_sizes.clone()))
	}

	pub fn as_tags_tree(&self) -> TypeSignatureTag {
		let mut stream = Cursor::new(self.0);
		TypeSignatureTag::read(&mut stream, &self.1).unwrap()
	}
}

/// These are used extensively in metadata signature blobs.
#[repr(u8)]
#[derive(Debug)]
pub enum TypeSignatureTag<'l> {
	/// Marks end of a list.
	End = 0x00,
	Void = 0x01,
	Bool = 0x02,
	Char = 0x03,
	Int1 = 0x04,
	UInt1 = 0x05,
	Int2 = 0x06,
	UInt2 = 0x07,
	Int4 = 0x08,
	UInt4 = 0x09,
	Int8 = 0x0a,
	UInt8 = 0x0b,
	Float = 0x0c,
	Double = 0x0d,
	String = 0x0e,
	/// Followed by type.
	Pointer(TypeSignature<'l>) = 0x0f,
	/// Followed by type.
	Reference(TypeSignature<'l>) = 0x10,
	/// Followed by TypeDef or TypeRef token.
	ValueType(TypeDefOrRef) = 0x11,
	/// Followed by TypeDef or TypeRef token.
	ClassType(TypeDefOrRef) = 0x12,
	/// Generic parameter in a generic type definition, represented as number (compressed unsigned integer).
	GenericParam(u32) = 0x13,
	/// Followed by: type, rank, boundsCount, \[bounds...], loCount, \[lo...].
	Array = 0x14,
	/// Generic type instantiation. Followed by type type-arg-count type-1 ... type-n.
	GenericInst(GenericInst<'l>) = 0x15,
	/// Undocumented
	TypedByRef = 0x16,
	/// System.IntPtr.
	IntPtr = 0x18,
	/// System.UIntPtr.
	UIntPtr = 0x19,
	/// Followed by full method signature.
	FnPointer(MethodSignature<'l>) = 0x1b,
	/// System.Object.
	Object = 0x1c,
	/// Single-dim array with 0 lower bound.
	SzArray(TypeSignature<'l>) = 0x1d,
	/// Generic parameter in a generic method definition, represented as number (compressed unsigned integer).
	MethodGenericParam(u32) = 0x1e,
	/// Required modifier : followed by a TypeDef or TypeRef token.
	CModReq = 0x1f,
	/// Optional modifier : followed by a TypeDef or TypeRef token.
	CModOpt(TypeDefOrRef) = 0x20,
	/// Implemented within the CLI.
	Internal = 0x21,
	/// Or’d with following element types.
	Mod = 0x40,
	/// Sentinel for vararg method signature.
	Sentinel = 0x41,
	/// Denotes a local variable that points at a pinned object.
	Pinned(TypeSignature<'l>) = 0x45,
	/// Indicates an argument of type System.Type.
	Type = 0x50,
	/// Used in custom attributes to specify a boxed object.
	CAttrBoxed = 0x51,
	/// Used in custom attributes to indicate a FIELD.
	CAttrFld = 0x53,
	/// Used in custom attributes to indicate a PROPERTY.
	CAttrProp = 0x54,
	/// Used in custom attributes to specify an enum.
	CAttrEnum = 0x55,
}

impl<'l> TypeSignatureTag<'l> {
	pub fn read(stream: &mut Cursor<&'l [u8]>, index_sizes: &Arc<IndexSizes>) -> Result<Self> {
		let tag = u8::read(stream, &())?;
		match tag {
			0x00 => Ok(TypeSignatureTag::End),
			0x01 => Ok(TypeSignatureTag::Void),
			0x02 => Ok(TypeSignatureTag::Bool),
			0x03 => Ok(TypeSignatureTag::Char),
			0x04 => Ok(TypeSignatureTag::Int1),
			0x05 => Ok(TypeSignatureTag::UInt2),
			0x06 => Ok(TypeSignatureTag::Int2),
			0x07 => Ok(TypeSignatureTag::UInt2),
			0x08 => Ok(TypeSignatureTag::Int4),
			0x09 => Ok(TypeSignatureTag::UInt4),
			0x0A => Ok(TypeSignatureTag::Int8),
			0x0B => Ok(TypeSignatureTag::UInt8),
			0x0C => Ok(TypeSignatureTag::Float),
			0x0D => Ok(TypeSignatureTag::Double),
			0x0E => Ok(TypeSignatureTag::String),
			0x0F => Ok(TypeSignatureTag::Pointer(TypeSignature::read(stream, index_sizes)?)),
			0x10 => Ok(TypeSignatureTag::Reference(TypeSignature::read(stream, index_sizes)?)),
			0x11 => Ok(TypeSignatureTag::ValueType(TypeDefOrRef::read_compressed(stream)?)),
			0x12 => Ok(TypeSignatureTag::ClassType(TypeDefOrRef::read_compressed(stream)?)),
			0x13 => Ok(TypeSignatureTag::GenericParam(read_compressed_u32(stream)?)),
			0x15 => Ok(TypeSignatureTag::GenericInst(GenericInst::read(stream, index_sizes)?)),
			0x16 => Ok(TypeSignatureTag::TypedByRef),
			0x18 => Ok(TypeSignatureTag::IntPtr),
			0x19 => Ok(TypeSignatureTag::UIntPtr),
			0x1B => Ok(TypeSignatureTag::FnPointer(MethodSignature::read(stream, index_sizes)?)),
			0x1C => Ok(TypeSignatureTag::Object),
			0x1D => Ok(TypeSignatureTag::SzArray(TypeSignature::read(stream, index_sizes)?)),
			0x1E => Ok(TypeSignatureTag::MethodGenericParam(read_compressed_u32(stream)?)),
			0x20 => Ok(TypeSignatureTag::CModOpt(TypeDefOrRef::read_compressed(stream)?)),
			0x45 => Ok(TypeSignatureTag::Pinned(TypeSignature::read(stream, index_sizes)?)),
			_ => unimplemented!("Unimplemented TypeSignature tag {:#X?}", tag),
		}
	}
}

pub struct GenericInst<'l>(TypeSignature<'l>, TypeSignatureSequence<'l>);

impl<'l> GenericInst<'l> {
	pub fn read(stream: &mut Cursor<&'l [u8]>, index_sizes: &Arc<IndexSizes>) -> Result<Self> {
		let ty = TypeSignature::read(stream, index_sizes)?;
		let seq = TypeSignatureSequence::read(stream, index_sizes)?;
		Ok(Self(ty, seq))
	}

	pub fn ty(&self) -> &TypeSignature {
		&self.0
	}

	pub fn params(&self) -> impl Iterator<Item=TypeSignatureTag<'l>> + '_ {
		self.1.signatures()
	}

	#[inline]
	pub fn params_count(&self) -> usize {
		self.1.len()
	}
}

impl<'l> Debug for GenericInst<'l> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		let mut dbg = f.debug_struct("GenericInst");
		dbg.field("ty", &self.0);
		dbg.field("params", &self.1);
		dbg.finish()
	}
}

pub struct TypeSignatureSequence<'l>(u32, &'l [u8], Arc<IndexSizes>);

impl<'l> TypeSignatureSequence<'l> {
	#[inline]
	pub fn len(&self) -> usize {
		self.0 as usize
	}

	#[inline]
	pub fn is_empty(&self) -> bool {
		self.0 == 0
	}

	pub fn signatures(&self) -> impl Iterator<Item=TypeSignatureTag<'l>> + '_ {
		let mut stream = Cursor::new(self.1);
		(0..self.0).map(move |_| TypeSignatureTag::read(&mut stream, &self.2).unwrap())
	}

	pub fn read(stream: &mut Cursor<&'l [u8]>, index_sizes: &Arc<IndexSizes>) -> Result<Self> {
		let count = read_compressed_u32(stream)?;
		Self::read_n(stream, index_sizes, count)
	}

	pub fn read_n(stream: &mut Cursor<&'l [u8]>, index_sizes: &Arc<IndexSizes>, count: u32) -> Result<Self> {
		let start = stream.position() as usize;
		for _ in 0..count {
			let _ = TypeSignature::read(stream, index_sizes)?;
		}
		let end = stream.position() as usize;
		Ok(Self(count, &stream.get_ref()[start..end], index_sizes.clone()))
	}
}

impl Debug for TypeSignatureSequence<'_> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		let mut dbg = f.debug_list();
		for sig in self.signatures() {
			dbg.entry(&sig);
		}
		dbg.finish()
	}
}

bitflags! {
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct CallingConvention: u8 {
		const DEFAULT = 0x0;
		const C	= 0x1;
		const STD_CALL = 0x2;
		const THIS_CALL = 0x3;
		const FAST_CALL = 0x4;
		const VAR_ARG = 0x5;
		const UNMANAGED = 0x9;
		const GENERIC = 0x10;
		const HAS_THIS = 0x20;
		const EXPLICIT_THIS = 0x40;
	}
}

impl_from_byte_stream!(CallingConvention);

#[derive(Debug)]
pub struct MethodSignature<'l> {
	calling_convention: CallingConvention,
	return_type: TypeSignature<'l>,
	parameter_types: TypeSignatureSequence<'l>,
}

impl<'l> MethodSignature<'l> {
	pub fn read(stream: &mut Cursor<&'l [u8]>, index_sizes: &Arc<IndexSizes>) -> Result<Self> {
		let calling_convention = CallingConvention::read(stream, &())?;

		if calling_convention.contains(CallingConvention::GENERIC) {
			let _count = read_compressed_u32(stream)?;
			// TODO handle generic call
		}

		let param_count = read_compressed_u32(stream)?;
		let return_type = TypeSignature::read(stream, index_sizes)?;

		Ok(
			Self {
				calling_convention,
				return_type,
				parameter_types: TypeSignatureSequence::read_n(stream, index_sizes, param_count)?,
			}
		)
	}
}
