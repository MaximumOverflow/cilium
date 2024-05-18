mod table;
use proc_macro::TokenStream;

#[proc_macro_derive(Table)]
pub fn derive_table(input: TokenStream) -> TokenStream {
    table::derive(input).into()
}
