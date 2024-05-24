use std::fmt::{Debug, Formatter};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use bumpalo::Bump;
use derivative::Derivative;
use fxhash::FxHashMap;
use rust_search::SearchBuilder;
use tracing::{debug, info};

use crate::raw::heaps::table::AssemblyFlags;
use crate::structured::assembly::{Assembly, AssemblyName, AssemblyVersion, OwnedAssemblyName};
use crate::structured::Context;

pub enum AssemblyResolverResult<'l> {
	None,
	Path(PathBuf),
	Assembly(&'l Assembly<'l>),
}

pub trait AssemblyResolver: Debug {
	fn resolve_assembly_name<'l>(&mut self, ctx: &Context<'l>, name: &AssemblyName) -> AssemblyResolverResult<'l>;
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct DefaultAssemblyResolver {
	bump: Bump,
	paths: FxHashMap<String, Vec<Rc<Path>>>,
	#[derivative(Debug(format_with = "DefaultAssemblyResolver::fmt_names"))]
	names: FxHashMap<Rc<OwnedAssemblyName>, Rc<Path>>,
	#[derivative(Debug(format_with = "DefaultAssemblyResolver::fmt_filtered_names"))]
	filtered_names: FxHashMap<String, Vec<Rc<OwnedAssemblyName>>>,
}

impl DefaultAssemblyResolver {
	pub fn new<T: AsRef<Path>>(paths: impl IntoIterator<Item=T>) -> DefaultAssemblyResolver {
		#[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
		fn gather_paths(res: &mut DefaultAssemblyResolver, path: &Path) {
			for entry in SearchBuilder::default().location(path).depth(usize::MAX).ext("dll").build() {
				let path = Path::new(&entry);
				let name_start = entry.as_bytes().iter().rposition(|b| matches!(*b, b'\\' | b'/')).map(|i| i + 1).unwrap_or(0);
				let name_end = entry.as_bytes().iter().rposition(|b| *b == b'.').unwrap_or(entry.len());
				let name = entry[name_start..name_end].to_string();
				res.paths.entry(name).or_default().push(Rc::from(path))
			}
		}

		let mut res = DefaultAssemblyResolver {
			bump: Default::default(),
			paths: Default::default(),
			names: Default::default(),
			filtered_names: Default::default(),
		};

		for path in paths {
			gather_paths(&mut res, path.as_ref());
		}

		res
	}
}

impl AssemblyResolver for DefaultAssemblyResolver {
	#[cfg_attr(feature = "tracing", tracing::instrument(skip(ctx)))]
	fn resolve_assembly_name<'l>(&mut self, ctx: &Context<'l>, name: &AssemblyName) -> AssemblyResolverResult<'l> {
		if let Some(ass) = ctx.loaded_assemblies().get(name) {
			return AssemblyResolverResult::Assembly(ass);
		}

		let mut name = OwnedAssemblyName::from(*name);

		if let Some(ass) = self.names.get(&name) {
			return AssemblyResolverResult::Path(ass.to_path_buf());
		}

		let Some(paths) = self.paths.get_mut(name.name.as_ref()) else {
			return AssemblyResolverResult::None;
		};

		let names = self.filtered_names.entry(name.name.to_string()).or_insert_with(|| {
			debug!("Enumerating assembly names for {:?}", name.name);
			let mut names = Vec::with_capacity(paths.len());
			for path in &*paths {
				self.bump.reset();
				let Ok(name) = AssemblyName::from_path(&self.bump, path) else { continue };
				let name = Rc::new(OwnedAssemblyName::from(*name));
				self.names.insert(name.clone(), path.clone());
				names.push(name);
			}
			names
		});

		if name.flags.contains(AssemblyFlags::RETARGETABLE) {
			name.version = AssemblyVersion::ZERO;
		}

		let result = names.iter()
			.filter(|a| a.version.is_compatible_with(&name.version))
			.max_by_key(|a| a.version);

		return match result {
			None => AssemblyResolverResult::None,
			Some(ass) => {
				self.bump.reset();
				let name = AssemblyName::from_owned(ass, &self.bump);
				match ctx.loaded_assemblies().get(&name) {
					Some(ass) => AssemblyResolverResult::Assembly(ass),
					None => AssemblyResolverResult::Path(self.names[&*ass].to_path_buf())
				}
			}
		};
	}
}

impl DefaultAssemblyResolver {
	fn fmt_names(names: &FxHashMap<Rc<OwnedAssemblyName>, Rc<Path>>, fmt: &mut Formatter) -> std::fmt::Result {
		let name = format!("[{}]", names.len());
		let mut dbg = fmt.debug_struct(&name);
		for (key, value) in names {
			let key = format!("{key}");
			dbg.field(&key, &format_args!("{value:?}"));
		}
		dbg.finish()
	}

	fn fmt_filtered_names(names: &FxHashMap<String, Vec<Rc<OwnedAssemblyName>>>, fmt: &mut Formatter) -> std::fmt::Result {
		struct Wrapper<'l>(&'l [Rc<OwnedAssemblyName>]);
		impl Debug for Wrapper<'_> {
			fn fmt(&self, fmt: &mut Formatter<'_>) -> std::fmt::Result {
				let mut dbg = fmt.debug_list();
				for value in self.0 {
					dbg.entry(&format_args!("{value}"));
				}
				dbg.finish()
			}
		}

		let alternate = fmt.alternate();

		let name = format!("[{}]", names.len());
		let mut dbg = fmt.debug_struct(&name);
		for (key, value) in names {
			match alternate {
				true => dbg.field(key, &format_args!("{:#?}", Wrapper(value))),
				false => dbg.field(key, &format_args!("{:?}", Wrapper(value))),
			};
		}
		dbg.finish()
	}
}
