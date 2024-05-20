use crate::raw::indices::metadata_token::MethodDef;
use crate::schema::heaps::InternedString;

#[derive(Debug)]
pub struct Method<'l> {
	pub(crate) metadata_token: MethodDef,
	pub(crate) name: InternedString<'l>,
}
