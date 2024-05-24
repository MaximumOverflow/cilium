use std::cell::{Ref, RefCell};
use std::path::Path;
use std::pin::Pin;

use bumpalo::Bump;
use derivative::Derivative;
use fxhash::FxHashMap;

use crate::structured::assembly::{Assembly, AssemblyLoadingError, AssemblyName};
use crate::structured::resolver::{AssemblyResolver, AssemblyResolverResult, DefaultAssemblyResolver};

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Context<'l> {
	#[derivative(Debug = "ignore")]
	bump: Pin<Box<Bump>>,
	#[derivative(Debug(format_with="crate::utilities::fmt_debug_values"))]
	loaded_assemblies: FxHashMap<&'l AssemblyName<'l>, &'l Assembly<'l>>,
	#[derivative(Debug = "ignore")]
	resolver: RefCell<Box<dyn AssemblyResolver>>,
}

impl<'l> Context<'l> {
	pub fn new<T: AsRef<Path>>(paths: impl IntoIterator<Item=T>) -> Self {
		Self::with_resolver(DefaultAssemblyResolver::new(paths))
	}

	pub fn with_resolver<T: AssemblyResolver + 'static>(resolver: T) -> Self {
		Context {
			bump: Pin::new(Box::new(Bump::new())),
			loaded_assemblies: Default::default(),
			resolver: RefCell::new(Box::new(resolver)),
		}
	}

	#[inline]
	pub fn loaded_assemblies(&self) -> &FxHashMap<&'l AssemblyName<'l>, &'l Assembly<'l>> {
		&self.loaded_assemblies
	}

	#[inline]
	pub fn load_assembly(&mut self, path: impl AsRef<Path>) -> Result<&'l Assembly<'l>, AssemblyLoadingError> {
		Assembly::load_from_path(self, &path)
	}

	#[inline]
	pub fn resolve_assembly_name(&self, name: &AssemblyName) -> AssemblyResolverResult<'l> {
		self.resolver.borrow_mut().resolve_assembly_name(self, name)
	}

	#[inline]
	pub fn assembly_resolver(&self) -> Ref<'_, Box<dyn AssemblyResolver>> {
		self.resolver.borrow()
	}

	#[inline]
	pub(crate) fn bump(&self) -> &'l Bump {
		unsafe { std::mem::transmute(&*self.bump) }
	}

	#[inline]
	pub(crate) fn loaded_assemblies_mut(&mut self) -> &mut FxHashMap<&'l AssemblyName<'l>, &'l Assembly<'l>> {
		&mut self.loaded_assemblies
	}
}
