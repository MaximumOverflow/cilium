use std::io::{Cursor, Error, ErrorKind, Read, Seek, SeekFrom};
use std::sync::Arc;

use bitflags::bitflags;

use crate::raw::heaps::{BlobHeap, GuidHeap, MetadataHeap, StringHeap, UserStringHeap};
use crate::raw::heaps::table::TableHeap;
use crate::raw::indices::metadata_token::MetadataToken;
use crate::raw::pe::{DataDirectory, ImageOptionalHeader, PEFile};
use crate::utilities::{FromByteStream, impl_from_byte_stream};

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct CLIHeader {
	pub size_in_bytes: u32,
	pub major_runtime_version: u16,
	pub minot_runtime_version: u16,
	pub metadata: DataDirectory,
	pub flags: RuntimeFlags,
	pub entry_point_token: MetadataToken,
	pub resources: DataDirectory,
	pub strong_name_signature: u64,
	pub code_manager_table: u64,
	pub v_table_fixups: u64,
	pub export_address_table_jumps: u64,
	pub managed_native_header: u64,
}

impl_from_byte_stream!(CLIHeader);

#[derive(Debug, Clone)]
pub struct MetadataRoot<'l> {
	major_version: u16,
	minor_version: u16,
	version: Arc<str>,
	flags: u16,
	heaps: Arc<[Arc<MetadataHeap<'l>>]>,
}

impl<'l> MetadataRoot<'l> {
	#[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
	pub fn read(data: &'l [u8]) -> std::io::Result<Self> {
		let mut stream = Cursor::new(data);
		if u32::read(&mut stream, &())? != 0x424A5342 {
			return Err(ErrorKind::InvalidData.into());
		}

		let major_version = u16::read(&mut stream, &())?;
		let minor_version = u16::read(&mut stream, &())?;
		stream.seek(SeekFrom::Current(4))?; // Reserved

		let length = ((u32::read(&mut stream, &())? + 3) / 4) * 4; // Round length to 4
		let mut bytes = vec![0; length as usize];
		stream.read_exact(&mut bytes)?;
		let Ok(version) = std::str::from_utf8(&bytes).map(Arc::<str>::from) else {
			return Err(ErrorKind::InvalidData.into());
		};

		let flags = u16::read(&mut stream, &())?;

		let stream_header_count = u16::read(&mut stream, &())? as usize;
		let mut heaps = vec![];
		for _ in 0..stream_header_count {
			let heap = MetadataHeap::read(&mut stream, data)?;
			heaps.push(heap);
		}

		Ok(Self {
			major_version,
			minor_version,
			version,
			flags,
			heaps: Arc::from(heaps),
		})
	}

	pub fn flags(&self) -> u16 {
		self.flags
	}
	pub fn version(&self) -> &str {
		&self.version
	}
	pub fn minor_version(&self) -> u16 {
		self.minor_version
	}
	pub fn major_version(&self) -> u16 {
		self.major_version
	}
	#[allow(private_bounds)]
	pub fn get_heap<T>(&self) -> Option<&T>
	where
		Self: GetHeap<T>,
	{
		<Self as GetHeap<T>>::get_heap(self)
	}
}

#[derive(Debug)]
pub struct Assembly<'l> {
	pe_file: PEFile<'l>,
	cli_header: CLIHeader,
	metadata_root: MetadataRoot<'l>,
}

bitflags! {
	#[derive(Debug, Copy, Clone, Eq, PartialEq)]
	pub struct RuntimeFlags: u32 {
		const IL_ONLY = 0x1;
		const REQUIRE_32_BIT = 0x2;
		const IL_LIBRARY= 0x4;
		const STRONG_NAME_SIGNED = 0x8;
		const PREFER_32_BIT = 0x00020000;
	}
}

impl<'l> TryFrom<PEFile<'l>> for Assembly<'l> {
	type Error = Error;
	#[cfg_attr(feature = "tracing", tracing::instrument(skip_all, name = "<Assembly as TryFrom<PEFile>>::try_from"))]
	fn try_from(pe: PEFile<'l>) -> Result<Self, Self::Error> {
		let rva = match &pe.pe_header.image_optional_header {
			ImageOptionalHeader::None => {
				return Err(Error::new(
					ErrorKind::InvalidData,
					"Missing optional PE header",
				))
			},
			ImageOptionalHeader::PE32(hdr) => {
				let Some(data_dir) = hdr.data_directories.get(14) else {
					return Err(ErrorKind::NotFound.into());
				};
				data_dir.virtual_address
			},
			ImageOptionalHeader::PE64(hdr) => {
				let Some(data_dir) = hdr.data_directories.get(14) else {
					return Err(ErrorKind::NotFound.into());
				};
				data_dir.virtual_address
			},
		};

		let Some((_, data, _)) = pe.resolve_rva(rva) else {
			return Err(ErrorKind::InvalidData.into());
		};
		let mut cursor = Cursor::new(data);
		let cli_header = CLIHeader::read(&mut cursor, &())?;

		let Some((_, data, _)) = pe.resolve_rva(cli_header.metadata.virtual_address) else {
			return Err(ErrorKind::InvalidData.into());
		};
		let metadata_root = MetadataRoot::read(data)?;

		Ok(Self {
			pe_file: pe,
			cli_header,
			metadata_root,
		})
	}
}

impl Assembly<'_> {
	pub fn pe_file(&self) -> &PEFile {
		&self.pe_file
	}
	pub fn cli_header(&self) -> CLIHeader {
		self.cli_header
	}
	pub fn metadata_root(&self) -> &MetadataRoot {
		&self.metadata_root
	}
}

trait GetHeap<T> {
	fn get_heap(&self) -> Option<&T>;
}

impl<'l> GetHeap<BlobHeap<'l>> for MetadataRoot<'l> {
	fn get_heap(&self) -> Option<&BlobHeap<'l>> {
		return self.heaps.iter().find_map(|h| match &**h {
			MetadataHeap::Blob(h) => Some(h),
			_ => None,
		});
	}
}

impl<'l> GetHeap<GuidHeap<'l>> for MetadataRoot<'l> {
	fn get_heap(&self) -> Option<&GuidHeap<'l>> {
		return self.heaps.iter().find_map(|h| match &**h {
			MetadataHeap::Guid(h) => Some(h),
			_ => None,
		});
	}
}

impl<'l> GetHeap<StringHeap<'l>> for MetadataRoot<'l> {
	fn get_heap(&self) -> Option<&StringHeap<'l>> {
		return self.heaps.iter().find_map(|h| match &**h {
			MetadataHeap::String(h) => Some(h),
			_ => None,
		});
	}
}

impl<'l> GetHeap<UserStringHeap<'l>> for MetadataRoot<'l> {
	fn get_heap(&self) -> Option<&UserStringHeap<'l>> {
		return self.heaps.iter().find_map(|h| match &**h {
			MetadataHeap::UserString(h) => Some(h),
			_ => None,
		});
	}
}

impl<'l> GetHeap<TableHeap<'l>> for MetadataRoot<'l> {
	fn get_heap(&self) -> Option<&TableHeap<'l>> {
		return self.heaps.iter().find_map(|h| match &**h {
			MetadataHeap::Table(h) => Some(h),
			_ => None,
		});
	}
}
