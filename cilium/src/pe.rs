use crate::utilities::impl_from_bytes;
use std::fmt::{Debug, Formatter};
use std::mem::size_of;
use std::ops::Range;
use std::sync::Arc;

#[repr(C)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PEFile {
	pub dos_header: DOSHeader,
	pub pe_header: PEHeader,
	pub sections: Vec<Section>,
}

impl PEFile {
	pub fn resolve_rva(&self, rva: u32) -> Option<(&[u8], usize)> {
		let section = self.sections
			.iter()
			.find(|s| s.virtual_data_range().contains(&rva))?;
		let idx = rva - section.header.virtual_address;
		Some((&section.data, idx as usize))
	}
}

impl TryFrom<&[u8]> for PEFile {
	type Error = &'static str;
	fn try_from(mut value: &[u8]) -> Result<Self, Self::Error> {
		if value.len() < DOS_HDR_SIZE {
			return Err("Invalid buffer size");
		}
		let dos_header = DOSHeader::try_from(&value[..DOS_HDR_SIZE])?;

		if value.len() < dos_header.new_header_start as usize {
			return Err("Invalid buffer size");
		}
		let pe_header = PEHeader::try_from(&value[dos_header.new_header_start as usize..])?;

		let mut sections_offset
			= dos_header.new_header_start as usize
			+ FILE_HDR_SIZE + 4
			+ pe_header.image_file_header.size_of_optional_header as usize;

		let mut section_headers = &value[sections_offset..];
		let mut sections = Vec::with_capacity(pe_header.image_file_header.number_of_sections as usize);
		for _ in 0..pe_header.image_file_header.number_of_sections as usize {
			let Some(header) = section_headers.get(0..SEC_HDR_SIZE) else {
				return Err("Invalid section header offset");
			};
			let header = SectionHeader::try_from(header)?;
			let start = header.pointer_to_raw_data as usize;
			let end = start + header.size_of_raw_data as usize;
			let Some(data) = value.get(start..end) else {
				return Err("Invalid section data offset");
			};
			sections.push(Section {
				header,
				data: Arc::from(data),
			});
			section_headers = &section_headers[size_of::<SectionHeader>()..];
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

impl_from_bytes!(DOSHeader, 0x5A4D);

#[repr(C)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PEHeader {
	pub magic: u32, // Must be 0x4550
	pub image_file_header: ImageFileHeader,
	pub image_optional_header: ImageOptionalHeader,
}

impl TryFrom<&[u8]> for PEHeader {
	type Error = &'static str;
	fn try_from(mut value: &[u8]) -> Result<Self, Self::Error> {
		if value.len() < FILE_HDR_SIZE + 4 {
			return Err("Invalid buffer size");
		}
		if u32::from_le_bytes(value[0..4].try_into().unwrap()) != 0x4550 {
			return Err("Magic value does not match");
		}
		value = &value[4..];
		let image_file_header = ImageFileHeader::try_from(
			&value[..FILE_HDR_SIZE]
		)?;
		value = &value[FILE_HDR_SIZE..];
		if value.len() < image_file_header.size_of_optional_header as usize {
			return Err("Invalid buffer size");
		}
		let image_optional_header = ImageOptionalHeader::try_from(
			&value[..image_file_header.size_of_optional_header as usize]
		)?;
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

impl_from_bytes!(ImageFileHeader);

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

impl_from_bytes!(ImageOptionalHeader32, 0x010B);

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

impl_from_bytes!(ImageOptionalHeader64, 0x020B);

#[repr(C, u16)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ImageOptionalHeader {
	None = 0x00,
	PE32(ImageOptionalHeader32) = 0x010B,
	PE64(ImageOptionalHeader64) = 0x020B,
}

impl TryFrom<&[u8]> for ImageOptionalHeader {
	type Error = &'static str;
	fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
		if value.is_empty() {
			return Ok(Self::None);
		}
		if value.len() < 2 {
			return Err("Invalid buffer size");
		}
		match u16::from_le_bytes(value[..2].try_into().unwrap()) {
			0x010B => Ok(Self::PE32(ImageOptionalHeader32::try_from(value)?)),
			0x020B => Ok(Self::PE64(ImageOptionalHeader64::try_from(value)?)),
			_ => Err("Magic value does not match")
		}
	}
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct DataDirectory {
	pub virtual_address: u32,
	pub size: u32,
}

impl_from_bytes!(DataDirectory);

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

impl_from_bytes!(SectionHeader);

#[derive(Clone, Eq, PartialEq)]
pub struct Section {
	pub header: SectionHeader,
	pub data: Arc<[u8]>,
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

const DOS_HDR_SIZE: usize = size_of::<DOSHeader>();
const SEC_HDR_SIZE: usize = size_of::<SectionHeader>();
const DATA_DIR_SIZE: usize = size_of::<DataDirectory>();
const FILE_HDR_SIZE: usize = size_of::<ImageFileHeader>();
const OPT_PE32_SIZE: usize = size_of::<ImageOptionalHeader32>();
const OPT_PE64_SIZE: usize = size_of::<ImageOptionalHeader64>();
