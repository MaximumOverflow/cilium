use std::cell::Cell;
use std::fmt::{Display, Formatter};
use std::io::ErrorKind;
use std::path::Path;

use bumpalo::Bump;
use derivative::Derivative;

use crate::raw::heaps::{BlobHeap, StringHeap};
use crate::raw::heaps::table::{Assembly as AssemblyRow, AssemblyFlags, AssemblyRef as AssemblyRefRow, TableHeap};
use crate::raw::pe::PEFile;
use crate::structured::Context;
use crate::structured::resolver::AssemblyResolverResult;
use crate::structured::types::{load_type_defs, populate_type_defs, Type};

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct AssemblyVersion {
	pub major_version: u16,
	pub minor_version: u16,
	pub build_number: u16,
	pub revision_number: u16,
}

impl AssemblyVersion {
	pub const ZERO: AssemblyVersion = AssemblyVersion {
		major_version: 0,
		minor_version: 0,
		build_number: 0,
		revision_number: 0,
	};

	#[inline]
	pub fn is_compatible_with(&self, other: &AssemblyVersion) -> bool {
		*self == Self::ZERO || *other == Self::ZERO ||
			(self.major_version == other.major_version && self.minor_version >= self.minor_version)
	}
}

impl Display for AssemblyVersion {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		write! {
			f, "{}.{}.{}.{}",
			self.major_version,
			self.minor_version,
			self.build_number,
			self.revision_number,
		}
	}
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Derivative)]
#[derivative(Debug)]
pub struct AssemblyName<'l> {
	pub version: AssemblyVersion,
	pub flags: AssemblyFlags,
	#[derivative(Debug(format_with="crate::utilities::fmt_as_hex"))]
	pub public_key: &'l [u8],
	pub name: &'l str,
	pub culture: &'l str,
}

impl<'l> AssemblyName<'l> {
	pub fn from_owned(owned: &OwnedAssemblyName, bump: &'l Bump) -> Self {
		Self {
			version: owned.version,
			flags: owned.flags,
			public_key: bump.alloc_slice_copy(&owned.public_key),
			name: bump.alloc_str(&owned.name),
			culture: bump.alloc_str(&owned.culture),
		}
	}

	#[inline]
	pub(crate) fn from_path(bump: &'l Bump, path: impl AsRef<Path>) -> std::io::Result<&'l AssemblyName> {
		#[inline(never)]
		fn from_path<'l>(bump: &'l Bump, path: &Path) -> std::io::Result<&'l AssemblyName<'l>> {
			#[cfg(feature = "memmap2")] let file = std::fs::File::open(&path)?;
			#[cfg(feature = "memmap2")] let mem = unsafe { memmap2::Mmap::map(&file) }?;
			#[cfg(feature = "memmap2")] let bytes = mem.as_ref();
			#[cfg(not(feature = "memmap2"))] let vec = std::fs::read(&path)?;
			#[cfg(not(feature = "memmap2"))] let bytes = vec.as_slice();

			let pe = PEFile::try_from(bytes) ?;
			let raw = crate::raw::assembly::Assembly::try_from(pe)?;
			let tables = raw.metadata_root().get_heap::<TableHeap>().ok_or(ErrorKind::NotFound)?;
			let table = tables.get_table::<AssemblyRow>().ok_or(ErrorKind::NotFound)?;
			let name_def = table.get(0)?;

			let blobs = raw.metadata_root().get_heap::<BlobHeap>().ok_or(ErrorKind::NotFound)?;
			let strings = raw.metadata_root().get_heap::<StringHeap>().ok_or(ErrorKind::NotFound)?;

			let public_key = blobs.get(name_def.public_key).ok_or(ErrorKind::NotFound)?;
			let culture = strings.get(name_def.culture).ok_or(ErrorKind::NotFound)?;
			let name = strings.get(name_def.name).ok_or(ErrorKind::NotFound)?;

			let name = bump.alloc(AssemblyName {
				version: AssemblyVersion {
					major_version: name_def.major_version,
					minor_version: name_def.minor_version,
					build_number: name_def.build_number,
					revision_number: name_def.revision_number,
				},
				flags: name_def.flags,
				public_key: bump.alloc_slice_copy(public_key),
				name: bump.alloc_str(name),
				culture: bump.alloc_str(culture),
			});
			Ok(name)
		}

		from_path(bump, path.as_ref())
	}
}

impl Display for AssemblyName<'_> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		let culture = match self.culture {
			"" => "neutral",
			_ => self.culture,
		};
		write! {
			f, "\"{}, Version={}, Culture={}, PublicKeyToken=",
			self.name, self.version, culture
		}?;
		match self.public_key {
			[] => write!(f, "null\""),
			_ => {
				for b in self.public_key {
					write!(f, "{:X}", b)?;
				}
				write!(f, "\"")
			},
		}
	}
}

#[derive(Clone, Eq, PartialEq, Hash, Derivative)]
#[derivative(Debug)]
pub struct OwnedAssemblyName {
	pub version: AssemblyVersion,
	pub flags: AssemblyFlags,
	#[derivative(Debug(format_with="crate::utilities::fmt_as_hex"))]
	pub public_key: Box<[u8]>,
	pub name: Box<str>,
	pub culture: Box<str>,
}

impl Display for OwnedAssemblyName {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		let culture = match self.culture.as_ref() {
			"" => "neutral",
			_ => self.culture.as_ref(),
		};
		write! {
			f, "\"{}, Version={}, Culture={}, PublicKeyToken=",
			self.name, self.version, culture
		}?;
		match self.public_key.as_ref() {
			[] => write!(f, "null\""),
			_ => {
				for b in self.public_key.as_ref() {
					write!(f, "{:X}", b)?;
				}
				write!(f, "\"")
			},
		}
	}
}

impl From<AssemblyName<'_>> for OwnedAssemblyName {
	fn from(value: AssemblyName<'_>) -> Self {
		Self {
			version: value.version,
			flags: value.flags,
			public_key: value.public_key.into(),
			name: value.name.into(),
			culture: value.culture.into(),
		}
	}
}

#[derive(Debug, Copy, Clone)]
pub enum AssemblyRef<'l> {
	Loaded(&'l Assembly<'l>),
	NotLoaded(&'l AssemblyName<'l>),
}

impl Display for AssemblyRef<'_> {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		match self {
			AssemblyRef::Loaded(v) => Display::fmt(v.name, f),
			AssemblyRef::NotLoaded(v) => write!(f, "{v} [!]"),
		}
	}
}

impl<'l> From<&'l Assembly<'l>> for AssemblyRef<'l> {
	fn from(value: &'l Assembly<'l>) -> Self {
		AssemblyRef::Loaded(value)
	}
}

impl<'l> From<&'l AssemblyName<'l>> for AssemblyRef<'l> {
	fn from(value: &'l AssemblyName<'l>) -> Self {
		AssemblyRef::NotLoaded(value)
	}
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Assembly<'l> {
	name: &'l AssemblyName<'l>,
	#[derivative(Debug(format_with = "crate::utilities::fmt_display_cell"))]
	refs: Cell<&'l [AssemblyRef<'l>]>,
	#[derivative(Debug(format_with = "crate::utilities::fmt_debug_cell"))]
	type_defs: Cell<&'l [Type<'l>]>,
}

impl<'l> Assembly<'l> {
	pub fn name(&self) -> &'l AssemblyName<'l> {
		self.name
	}

	pub fn refs(&self) -> &'l [AssemblyRef<'l>] {
		self.refs.get()
	}

	pub fn types(&self) -> &'l [Type<'l>] {
		self.type_defs.get()
	}

	#[inline]
	pub(crate) fn load_from_path(ctx: &mut Context<'l>, path: impl AsRef<Path>) -> Result<&'l Assembly<'l>, AssemblyLoadingError> {
		#[inline(never)]
		pub(crate) fn load_from_path<'l>(ctx: &mut Context<'l>, path: impl AsRef<Path>) -> Result<&'l Assembly<'l>, AssemblyLoadingError> {
			#[cfg(feature = "memmap2")] let file = std::fs::File::open(&path)?;
			#[cfg(feature = "memmap2")] let mem = unsafe { memmap2::Mmap::map(&file) }?;
			#[cfg(feature = "memmap2")] let bytes = mem.as_ref();
			#[cfg(not(feature = "memmap2"))] let vec = std::fs::read(&path)?;
			#[cfg(not(feature = "memmap2"))] let bytes = vec.as_slice();

			let bump = ctx.bump();
			let pe = PEFile::try_from(bytes)?;
			let raw = crate::raw::assembly::Assembly::try_from(pe)?;
			let tables = raw.metadata_root().get_heap::<TableHeap>().ok_or(ErrorKind::NotFound)?;

			let blobs = raw.metadata_root().get_heap::<BlobHeap>().ok_or(ErrorKind::NotFound)?;
			let strings = raw.metadata_root().get_heap::<StringHeap>().ok_or(ErrorKind::NotFound)?;

			let name = {
				let table = tables.get_table::<AssemblyRow>().ok_or(ErrorKind::NotFound)?;
				let name_def = table.get(0)?;

				let public_key = blobs.get(name_def.public_key).ok_or(ErrorKind::NotFound)?;
				let culture = strings.get(name_def.culture).ok_or(ErrorKind::NotFound)?;
				let name = strings.get(name_def.name).ok_or(ErrorKind::NotFound)?;

				if let Some(assembly) = ctx.loaded_assemblies().get(&AssemblyName {
					version: AssemblyVersion {
						major_version: name_def.major_version,
						minor_version: name_def.minor_version,
						build_number: name_def.build_number,
						revision_number: name_def.revision_number,
					},
					flags: name_def.flags,
					public_key,
					name,
					culture,
				}) {
					return Ok(*assembly)
				}

				bump.alloc(AssemblyName {
					version: AssemblyVersion {
						major_version: name_def.major_version,
						minor_version: name_def.minor_version,
						build_number: name_def.build_number,
						revision_number: name_def.revision_number,
					},
					flags: name_def.flags,
					public_key: bump.alloc_slice_copy(public_key),
					name: bump.alloc_str(name),
					culture: bump.alloc_str(culture),
				})
			};

			let assembly = bump.alloc(Assembly {
				name,
				refs: Cell::new(&[]),
				type_defs: Cell::new(&[]),
			});

			// Insert it early to fix circular dependencies
			ctx.loaded_assemblies_mut().insert(name, assembly);

			// Load assembly refs
			{
				let mut assembly_refs = vec![];
				if let Some(table) = tables.get_table::<AssemblyRefRow>() {
					assembly_refs.reserve_exact(table.len());
					for ass_ref in table.rows() {
						let ass_ref = ass_ref?;
						let public_key = blobs.get(ass_ref.public_key).ok_or(ErrorKind::NotFound)?;
						let culture = strings.get(ass_ref.culture).ok_or(ErrorKind::NotFound)?;
						let name = strings.get(ass_ref.name).ok_or(ErrorKind::NotFound)?;

						let ass_name = AssemblyName {
							version: AssemblyVersion {
								major_version: ass_ref.major_version,
								minor_version: ass_ref.minor_version,
								build_number: ass_ref.build_number,
								revision_number: ass_ref.revision_number,
							},
							flags: ass_ref.flags,
							public_key,
							culture,
							name,
						};

						match ctx.resolve_assembly_name(&ass_name) {
							AssemblyResolverResult::Path(path) => {
								let assembly = ctx.load_assembly(path)?;
								assembly_refs.push(assembly.into());
							}
							AssemblyResolverResult::Assembly(ass) => {
								assembly_refs.push(ass.into());
							}
							AssemblyResolverResult::None => {
								let name: &AssemblyName = bump.alloc(AssemblyName {
									version: AssemblyVersion {
										major_version: ass_ref.major_version,
										minor_version: ass_ref.minor_version,
										build_number: ass_ref.build_number,
										revision_number: ass_ref.revision_number,
									},
									flags: ass_ref.flags,
									public_key: bump.alloc_slice_copy(public_key),
									name: bump.alloc_str(name),
									culture: bump.alloc_str(culture),
								});
								assembly_refs.push(name.into());
							}
						}
					}

					assert_eq!(assembly_refs.len(), table.len());
				}
				assembly.refs.set(bump.alloc_slice_copy(&assembly_refs));
			}

			// Load type defs
			{
				let types = load_type_defs(bump, tables, *strings)?;
				assembly.type_defs.set(types);
			}

			populate_type_defs(bump, *blobs, *strings, tables, assembly)?;

			Ok(assembly)
		}

		load_from_path(ctx, path.as_ref())
	}
}

#[derive(Debug)]
pub enum AssemblyLoadingError {
	IoError(std::io::Error),
}

impl From<std::io::Error> for AssemblyLoadingError {
	#[inline]
	fn from(value: std::io::Error) -> Self {
		AssemblyLoadingError::IoError(value)
	}
}

impl From<ErrorKind> for AssemblyLoadingError {
	#[inline]
	fn from(value: ErrorKind) -> Self {
		AssemblyLoadingError::IoError(value.into())
	}
}
