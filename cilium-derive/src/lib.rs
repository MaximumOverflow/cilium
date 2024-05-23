mod from_repr;

use proc_macro::TokenStream;

#[proc_macro_derive(FromRepr)]
pub fn derive_from_repr(input: TokenStream) -> TokenStream {
	from_repr::derive(input).into()
}
