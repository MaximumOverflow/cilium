mod table;
mod from_repr;

use proc_macro::TokenStream;

#[proc_macro_derive(Table, attributes(read_with, print_rows))]
pub fn derive_table(input: TokenStream) -> TokenStream {
    table::derive(input).into()
}

#[proc_macro_derive(FromRepr)]
pub fn derive_from_repr(input: TokenStream) -> TokenStream {
    from_repr::derive(input).into()
}
