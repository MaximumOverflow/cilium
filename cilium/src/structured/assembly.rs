use derivative::Derivative;
use crate::raw::heaps::table::AssemblyFlags;

#[derive(Clone, Eq, PartialEq, Hash, Derivative)]
#[derivative(Debug)]
pub struct AssemblyName<'l> {
	pub major_version: u16,
	pub minor_version: u16,
	pub build_number: u16,
	pub revision_number: u16,
	pub flags: AssemblyFlags,
	#[derivative(Debug(format_with="crate::utilities::display_as_hex"))]
	pub public_key: &'l [u8],
	pub name: &'l str,
	pub culture: &'l str,
}

#[derive(Debug)]
pub struct Assembly<'l> {
	name: &'l AssemblyName<'l>,
}
