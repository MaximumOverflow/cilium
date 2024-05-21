use std::path::{Path, PathBuf};
use bumpalo::Bump;
use derivative::Derivative;
use fxhash::FxHashMap;
use crate::raw::assembly::Assembly as RawAssembly;
use crate::raw::heaps::{BlobHeap, StringHeap};
use crate::raw::heaps::table::{AssemblyTable, TableHeap};
use crate::raw::pe::PEFile;
use crate::structured::assembly::{Assembly, AssemblyName};

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Context<'l> {
	#[derivative(Debug="ignore")]
	bump: Bump,
	#[derivative(Debug(format_with="crate::utilities::display_as_values"))]
	assembly_files: FxHashMap<&'l AssemblyName<'l>, PathBuf>,
	#[derivative(Debug(format_with="crate::utilities::display_as_values"))]
	loaded_assemblies: FxHashMap<&'l AssemblyName<'l>, &'l Assembly<'l>>,
}

impl<'l> Context<'l> {
	pub fn new<T: AsRef<Path>>(search_paths: impl IntoIterator<Item=T>) -> Self {
		let mut ctx = Context {
			bump: Default::default(),
			assembly_files: Default::default(),
			loaded_assemblies: Default::default(),
		};

		for dir in search_paths {
			let dir = dir.as_ref();
			let Ok(dir) = std::fs::read_dir(dir) else { continue };
			for entry in dir {
				let Ok(entry) = entry else { continue };
				let path = entry.path();
				let Some(extension) = path.extension() else { continue };
				let extension = extension.to_string_lossy();
				match extension.as_ref() {
					"dll" => ctx.try_add_assembly_path(path),
					_ => continue,
				}
			}
		}

		ctx
	}

	fn bump(&self) -> &'l Bump {
		unsafe { std::mem::transmute(&self.bump) }
	}

	#[inline(never)]
	fn try_add_assembly_path(&mut self, path: PathBuf) {
		#[cfg(feature = "memmap2")] let Ok(file) = std::fs::File::open(&path) else { return };
		#[cfg(feature = "memmap2")] let Ok(mem) = (unsafe { memmap2::Mmap::map(&file) }) else { return };
		#[cfg(feature = "memmap2")] let bytes = mem.as_ref();
		#[cfg(not(feature = "memmap2"))] let Ok(vec) = std::fs::read(&path) else { return };
		#[cfg(not(feature = "memmap2"))] let bytes = vec.as_slice();

		let Ok(pe) = PEFile::try_from(bytes) else { return };
		let Ok(raw) = RawAssembly::try_from(pe) else { return };
		let Some(tables) = raw.metadata_root().get_heap::<TableHeap>() else { return };
		let Some(table) = tables.get_table::<AssemblyTable>() else { return };
		let Ok(name_def) = table.get(0) else { return };

		let bump = self.bump();
		let Some(blobs) = raw.metadata_root().get_heap::<BlobHeap>() else { return };
		let Some(strings) = raw.metadata_root().get_heap::<StringHeap>() else { return };

		let Some(public_key) = blobs.get(name_def.public_key) else { return };
		let Some(culture) = strings.get(name_def.culture) else { return };
		let Some(name) = strings.get(name_def.name) else { return };

		let name = bump.alloc(AssemblyName {
			major_version: name_def.major_version,
			minor_version: name_def.minor_version,
			build_number: name_def.build_number,
			revision_number: name_def.revision_number,
			flags: name_def.flags,
			public_key: bump.alloc_slice_copy(public_key),
			name: bump.alloc_str(name),
			culture: bump.alloc_str(culture),
		});

		self.assembly_files.insert(name, path);
	}
}