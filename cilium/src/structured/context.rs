use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::path::{Path, PathBuf};
use std::pin::Pin;

use bumpalo::Bump;
use derivative::Derivative;
use fxhash::FxHashMap;
use uuid::Version;
use crate::raw::heaps::table::AssemblyFlags;

use crate::structured::assembly::{Assembly, AssemblyLoadingError, AssemblyName, AssemblyVersion};

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Context<'l> {
	#[derivative(Debug = "ignore")]
	bump: Pin<Box<Bump>>,
	#[derivative(Debug(format_with="fmt_reachable_assemblies"))]
	reachable_assemblies: FxHashMap<&'l AssemblyName<'l>, PathBuf>,
	#[derivative(Debug(format_with="crate::utilities::fmt_debug_values"))]
	loaded_assemblies: FxHashMap<&'l AssemblyName<'l>, &'l Assembly<'l>>,
	#[derivative(Debug = "ignore")]
	resolver: Box<dyn AssemblyResolver>,
}

impl<'l> Context<'l> {
	pub fn new<T: AsRef<Path>>(search_paths: impl IntoIterator<Item=T>) -> Self {
		let mut ctx = Context {
			bump: Pin::new(Box::new(Bump::new())),
			reachable_assemblies: Default::default(),
			loaded_assemblies: Default::default(),
			resolver: Box::new(DefaultAssemblyResolver),
		};

		fn add_paths(ctx: &mut Context, path: &Path) {
			let Ok(dir) = std::fs::read_dir(path) else { return };
			for entry in dir {
				let Ok(entry) = entry else { continue };
				let Ok(metadata) = entry.metadata() else { continue };

				let path = entry.path();

				if metadata.is_dir() {
					add_paths(ctx, &path);
				}
				else {
					let Some(extension) = path.extension() else { continue };
					let extension = extension.to_string_lossy();
					match extension.as_ref() {
						"dll" => ctx.try_add_assembly_path(path),
						_ => continue,
					}
				}
			}
		}

		for dir in search_paths {
			add_paths(&mut ctx, dir.as_ref());
		}
		ctx
	}

	#[inline]
	pub fn loaded_assemblies(&self) -> &FxHashMap<&'l AssemblyName<'l>, &'l Assembly<'l>> {
		&self.loaded_assemblies
	}

	#[inline]
	pub fn reachable_assemblies(&self) -> &FxHashMap<&'l AssemblyName<'l>, PathBuf> {
		&self.reachable_assemblies
	}

	#[inline]
	pub fn load_assembly(&mut self, path: impl AsRef<Path>) -> Result<&'l Assembly<'l>, AssemblyLoadingError> {
		Assembly::load_from_path(self, &path)
	}

	#[inline]
	pub fn resolve_assembly_name(&self, name: &AssemblyName) -> AssemblyResolverResult<'l> {
		self.resolver.resolve_assembly_name(self, name)
	}

	#[inline]
	pub(crate) fn bump(&self) -> &'l Bump {
		unsafe { std::mem::transmute(&*self.bump) }
	}

	#[inline]
	pub(crate) fn loaded_assemblies_mut(&mut self) -> &mut FxHashMap<&'l AssemblyName<'l>, &'l Assembly<'l>> {
		&mut self.loaded_assemblies
	}

	#[inline]
	fn try_add_assembly_path(&mut self, path: PathBuf) {
		if let Ok(name) = AssemblyName::from_path(self.bump(), &path) {
			self.reachable_assemblies.insert(name, path);
		};
	}
}

pub enum AssemblyResolverResult<'l> {
	None,
	Path(PathBuf),
	Assembly(&'l Assembly<'l>),
}

pub trait AssemblyResolver {
	fn resolve_assembly_name<'l>(&self, ctx: &Context<'l>, name: &AssemblyName) -> AssemblyResolverResult<'l>;
}

pub struct DefaultAssemblyResolver;

impl AssemblyResolver for DefaultAssemblyResolver {
	fn resolve_assembly_name<'l>(&self, ctx: &Context<'l>, name: &AssemblyName) -> AssemblyResolverResult<'l> {
		if let Some(ass) = ctx.loaded_assemblies.get(name) {
			return AssemblyResolverResult::Assembly(ass);
		}

		if let Some(path) = ctx.reachable_assemblies.get(name) {
			return AssemblyResolverResult::Path(path.clone());
		}

		let mut name = name.clone();
		if name.flags.contains(AssemblyFlags::RETARGETABLE) {
			name.version = AssemblyVersion::ZERO;
		}

		let result = ctx.reachable_assemblies.iter()
			.filter(|(a, _)| {
				a.name == name.name &&
					a.culture == name.culture &&
					a.version.is_compatible_with(&name.version)
			})
			.max_by_key(|(a, _)| a.version);

		return match result {
			None => AssemblyResolverResult::None,
			Some((name, path)) => match ctx.loaded_assemblies.get(name) {
				Some(ass) => AssemblyResolverResult::Assembly(ass),
				None => AssemblyResolverResult::Path(path.clone())
			}
		};

		AssemblyResolverResult::None
	}
}

pub(crate) fn fmt_reachable_assemblies(map: &FxHashMap<&AssemblyName, PathBuf>, fmt: &mut Formatter<'_>) -> std::fmt::Result {
	let mut dbg = fmt.debug_set();
	for (key, value) in map.iter() {
		dbg.entry(&format_args!("{key}: {value:?}"));
	}
	dbg.finish()
}
