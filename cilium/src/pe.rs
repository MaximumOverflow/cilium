use std::borrow::Borrow;
use std::fmt::{Debug, Formatter};
use std::io::{Cursor, Error, ErrorKind, Read, Seek, SeekFrom};
use std::mem::size_of;
use std::ops::Range;
use std::sync::Arc;
use owning_ref::ArcRef;

use crate::utilities::{FromByteStream, impl_from_byte_stream, read_bytes_slice_from_stream};

#[repr(C)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PEFile {
	pub dos_header: DOSHeader,
	pub pe_header: PEHeader,
	pub sections: Vec<Section>,
}

impl PEFile {
	pub fn resolve_rva(&self, rva: u32) -> Option<(&Section, ArcRef<[u8]>, usize)> {
		let section = self.sections
			.iter()
			.find(|s| s.virtual_data_range().contains(&rva))?;
		let idx = rva - section.header.virtual_address;
		Some((section, section.data.clone().map(|s| &s[idx as usize..]), idx as usize))
	}
}

impl FromByteStream for PEFile {
	fn read(stream: &mut Cursor<&[u8]>) -> std::io::Result<Self> {
		let dos_header = DOSHeader::read(stream)?;
		stream.set_position(dos_header.new_header_start as u64);
		let pe_header = PEHeader::read(stream)?;

		stream.set_position(
			dos_header.new_header_start as u64
				+ size_of::<ImageFileHeader>() as u64 + 4
				+ pe_header.image_file_header.size_of_optional_header as u64
		);

		let mut sections = Vec::with_capacity(pe_header.image_file_header.number_of_sections as usize);
		for _ in 0..pe_header.image_file_header.number_of_sections as usize {
			let header = SectionHeader::read(stream)?;
			let position = stream.position();
			stream.set_position(header.pointer_to_raw_data as u64);
			let data = read_bytes_slice_from_stream(stream, header.size_of_raw_data as usize)?;
			sections.push(Section {
				header,
				data: ArcRef::new(Arc::from(data)),
			});
			stream.set_position(position);
		}

		Ok(Self { dos_header, pe_header, sections })
	}
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct DOSHeader {
	pub magic: u16, // Must be 0x5A4D
	pub last_page_bytes: u16,
	pub file_pages: u16,
	pub relocations: u16,
	pub header_size: u16,
	pub min_alloc: u16,
	pub max_alloc: u16,
	pub ss: u16,
	pub sp: u16,
	pub checksum: u16,
	pub ip: u16,
	pub cs: u16,
	pub relocation_table_address: u16,
	pub overlay_number: u16,
	pub reserved: [u16; 4],
	pub oem_id: u16,
	pub oem_info: u16,
	pub reserved_2: [u16; 10],
	pub new_header_start: u32,
}

impl_from_byte_stream!(DOSHeader, 0x5A4D);

#[repr(C)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PEHeader {
	pub magic: u32, // Must be 0x4550
	pub image_file_header: ImageFileHeader,
	pub image_optional_header: ImageOptionalHeader,
}

impl FromByteStream for PEHeader {
	fn read(stream: &mut Cursor<&[u8]>) -> std::io::Result<Self> {
		if u32::read(stream)? != 0x4550 {
			return Err(Error::from(ErrorKind::InvalidData));
		}
		let image_file_header = ImageFileHeader::read(stream)?;
		let image_optional_header = ImageOptionalHeader::read(stream)?;
		Ok(Self {
			magic: 0x4550,
			image_file_header,
			image_optional_header,
		})
	}
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ImageFileHeader {
	pub machine: u16,
	pub number_of_sections: u16,
	pub time_date_stamp: u32,
	pub pointer_to_symbol_table: u32,
	pub number_of_symbols: u32,
	pub size_of_optional_header: u16,
	pub characteristics: u16,
}

impl_from_byte_stream!(ImageFileHeader);

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ImageOptionalHeader32 {
	pub magic: u16, // Must be 0x010B
	pub major_linker_version: u8,
	pub minor_linker_version: u8,
	pub size_of_code: u32,
	pub size_of_initialized_data: u32,
	pub size_of_uninitialized_data: u32,
	pub address_of_entry_point: u32,
	pub base_of_code: u32,
	pub base_of_data: u32,
	pub image_base: u32,
	pub section_alignment: u32,
	pub file_alignment: u32,
	pub major_operating_system_version: u16,
	pub minor_operating_system_version: u16,
	pub major_image_version: u16,
	pub minor_image_version: u16,
	pub major_subsystem_version: u16,
	pub minor_subsystem_version: u16,
	pub win32_version_value: u32,
	pub size_of_image: u32,
	pub size_of_headers: u32,
	pub check_sum: u32,
	pub subsystem: u16,
	pub dll_characteristics: u16,
	pub size_of_stack_reserve: u32,
	pub size_of_stack_commit: u32,
	pub size_of_heap_reserve: u32,
	pub size_of_heap_commit: u32,
	pub loader_flags: u32,
	pub number_of_rva_and_sizes: u32,
	pub data_directories: [DataDirectory; 16],
}

impl_from_byte_stream!(ImageOptionalHeader32, 0x010B);

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ImageOptionalHeader64 {
	pub magic: u16, // Must be 0x020B
	pub major_linker_version: u8,
	pub minor_linker_version: u8,
	pub size_of_code: u32,
	pub size_of_initialized_data: u32,
	pub size_of_uninitialized_data: u32,
	pub address_of_entry_point: u32,
	pub base_of_code: u32,
	pub image_base: u64,
	pub section_alignment: u32,
	pub file_alignment: u32,
	pub major_operating_system_version: u16,
	pub minor_operating_system_version: u16,
	pub major_image_version: u16,
	pub minor_image_version: u16,
	pub major_subsystem_version: u16,
	pub minor_subsystem_version: u16,
	pub win32_version_value: u32,
	pub size_of_image: u32,
	pub size_of_headers: u32,
	pub check_sum: u32,
	pub subsystem: u16,
	pub dll_characteristics: u16,
	pub size_of_stack_reserve: u64,
	pub size_of_stack_commit: u64,
	pub size_of_heap_reserve: u64,
	pub size_of_heap_commit: u64,
	pub loader_flags: u32,
	pub number_of_rva_and_sizes: u32,
	pub data_directories: [DataDirectory; 16],
}

impl_from_byte_stream!(ImageOptionalHeader64, 0x020B);

#[repr(C, u16)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ImageOptionalHeader {
	None = 0x00,
	PE32(ImageOptionalHeader32) = 0x010B,
	PE64(ImageOptionalHeader64) = 0x020B,
}

impl FromByteStream for ImageOptionalHeader {
	fn read(stream: &mut Cursor<&[u8]>) -> std::io::Result<Self> {
		let start = stream.position();
		match u16::read(stream)? {
			0x010B => {
				stream.set_position(start);
				Ok(Self::PE32(ImageOptionalHeader32::read(stream)?))
			}
			0x020B => {
				stream.set_position(start);
				Ok(Self::PE64(ImageOptionalHeader64::read(stream)?))
			}
			_ => Err(Error::from(ErrorKind::InvalidData)),
		}
	}
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct DataDirectory {
	pub virtual_address: u32,
	pub size: u32,
}

impl_from_byte_stream!(DataDirectory);

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct SectionName([u8; 8]);

impl AsRef<str> for SectionName {
	fn as_ref(&self) -> &str {
		match std::str::from_utf8(&self.0) {
			Err(_) => "INVALID UTF8",
			Ok(name) => name.trim_end_matches('\0'),
		}
	}
}

impl Debug for SectionName {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		write!(f, r#""{}""#, self.as_ref())
	}
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct SectionHeader {
	pub name: SectionName,
	pub physical_address_or_virtual_size: u32,
	pub virtual_address: u32,
	pub size_of_raw_data: u32,
	pub pointer_to_raw_data: u32,
	pub pointer_to_relocations: u32,
	pub pointer_to_line_numbers: u32,
	pub number_of_relocations: u16,
	pub number_of_line_numbers: u16,
	pub characteristics: u32,
}

impl_from_byte_stream!(SectionHeader);

#[derive(Clone, Eq, PartialEq)]
pub struct Section {
	pub header: SectionHeader,
	pub data: ArcRef<[u8]>,
}

impl Section {
	pub fn raw_data_range(&self) -> Range<u32> {
		self.header.pointer_to_raw_data..self.header.pointer_to_raw_data + self.header.size_of_raw_data
	}

	pub fn virtual_data_range(&self) -> Range<u32> {
		self.header.virtual_address..self.header.virtual_address + self.header.size_of_raw_data
	}
}

impl Debug for Section {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		let mut dbg = f.debug_struct("Section");
		dbg.field("header", &self.header);
		dbg.field("data", &format_args!("[u8; {:#X}]", self.data.len()));
		dbg.finish()
	}
}
