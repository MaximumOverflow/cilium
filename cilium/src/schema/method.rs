use derivative::Derivative;
use crate::raw::indices::metadata_token::MethodDef;
use crate::schema::heaps::InternedBlob;
use crate::schema::r#type::Type;

#[derive(Debug)]
pub struct Method<'l> {
	pub(crate) metadata_token: MethodDef,
	pub(crate) name: &'l str,
	pub(crate) body: Option<MethodBody<'l>>,
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct MethodBody<'l> {
	pub(crate) max_stack_size: u16,
	pub(crate) init_locals: bool,
	#[derivative(Debug(format_with="crate::raw::il::debug_opcodes"))]
	pub(crate) code: InternedBlob<'l>,
	#[derivative(Debug(format_with="crate::schema::r#type::fmt_display_types"))]
	pub(crate) locals: &'l [&'l Type<'l>],
}
