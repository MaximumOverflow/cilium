use std::collections::HashMap;
use std::io::{Cursor, ErrorKind, Read, Seek, SeekFrom};
use std::mem::size_of;
use std::sync::Arc;

use bitflags::bitflags;
use owning_ref::ArcRef;

use crate::heaps::{MetadataHeap, MetadataHeapKind};
use crate::indices::metadata_token::{MetadataToken, RawMetadataToken};
use crate::pe::{DataDirectory, ImageOptionalHeader, PEFile};
use crate::utilities::{FromByteStream, impl_from_byte_stream};

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct CLIHeader {
    pub size_in_bytes: u32,
    pub major_runtime_version: u16,
    pub minot_runtime_version: u16,
    pub metadata: DataDirectory,
    pub flags: RuntimeFlags,
    pub entry_point_token: RawMetadataToken,
    pub resources: DataDirectory,
    pub strong_name_signature: u64,
    pub code_manager_table: u64,
    pub v_table_fixups: u64,
    pub export_address_table_jumps: u64,
    pub managed_native_header: u64,
}

impl_from_byte_stream!(CLIHeader);

#[derive(Debug, Clone)]
pub struct MetadataRoot {
    pub major_version: u16,
    pub minor_version: u16,
    pub version: Arc<str>,
    pub flags: u16,
    pub heaps: HashMap<MetadataHeapKind, Arc<dyn MetadataHeap>>,
}

impl MetadataRoot {
    pub fn read(data: &ArcRef<[u8]>) -> std::io::Result<Self> {
        let mut stream = Cursor::new(data.as_ref());
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
        let mut heaps = HashMap::with_capacity(stream_header_count);
        for _ in 0..stream_header_count {
            let heap = <dyn MetadataHeap>::read(&mut stream, data)?;
            heaps.insert(heap.kind(), heap);
        }

        Ok(Self {
            major_version,
            minor_version,
            version,
            flags,
            heaps,
        })
    }
}

#[derive(Debug)]
pub struct Assembly {
    pe_file: PEFile,
    cli_header: CLIHeader,
    metadata_root: MetadataRoot,
}

bitflags! {
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    struct RuntimeFlags: u32 {
        const IL_ONLY = 0x1;
        const REQUIRE_32_BIT = 0x2;
		const IL_LIBRARY= 0x4;
		const STRONG_NAME_SIGNED = 0x8;
		const PREFER_32_BIT = 0x00020000;
    }
}

impl TryFrom<PEFile> for Assembly {
    type Error = std::io::Error;
    fn try_from(pe: PEFile) -> Result<Self, Self::Error> {
        let rva = match &pe.pe_header.image_optional_header {
            ImageOptionalHeader::None => panic!(),
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
        let mut cursor = Cursor::new(data.as_ref());
        let cli_header = CLIHeader::read(&mut cursor, &())?;

        let Some((_, data, _)) = pe.resolve_rva(cli_header.metadata.virtual_address) else {
            return Err(ErrorKind::InvalidData.into());
        };
        let metadata_root = MetadataRoot::read(&data)?;

        Ok(Self { pe_file: pe, cli_header, metadata_root })
    }
}

const CLI_HDR_SIZE: usize = size_of::<CLIHeader>();
