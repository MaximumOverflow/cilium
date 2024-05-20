use crate::raw::indices::metadata_token::MetadataToken;

#[derive(Debug)]
pub enum ReadError {
	IoError(std::io::Error),
	MissingMetadataHeap(&'static str),
	MissingMetadataTable(&'static str),

	InvalidStringToken(MetadataToken),

	#[cfg(feature = "memmap2")]
	MemMapError(memmap2::Error),
}

impl From<std::io::Error> for ReadError {
	fn from(value: std::io::Error) -> Self {
		Self::IoError(value)
	}
}

#[cfg(feature = "memmap2")]
impl From<memmap2::Error> for ReadError {
	fn from(value: memmap2::Error) -> Self {
		Self::IoError(value)
	}
}


