use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput};

pub fn derive(tokens: proc_macro::TokenStream) -> TokenStream {
	let DeriveInput {
		attrs,
		ident,
		generics,
		data,
		..
	} = syn::parse(tokens).unwrap();

	let data = match data {
		Data::Enum(data) => data,
		Data::Union(_) => panic!("Unions are not supported"),
		Data::Struct(_) => panic!("Structs are not supported"),
	};

	if !generics.params.is_empty() {
		panic!("Generics are not supported");
	}

	for attr in attrs.iter() {
		if attr.path().is_ident("repr") {
			unimplemented!()
		}
	}

	let mut cases = Vec::with_capacity(data.variants.len());
	let mut constants = Vec::with_capacity(data.variants.len());

	for (i, variant) in data.variants.iter().enumerate() {
		let Some((_, discriminant)) = &variant.discriminant else {
			panic!("Explicit discriminant required for `{}`", variant.ident);
		};
		let variant_name = &variant.ident;
		let ident = format_ident!("DISCRIMINANT_{i}");
		constants.push(quote! {
			const #ident: usize = #discriminant;
		});
		cases.push(quote! {
			#ident => Some(Self::#variant_name),
		});
	}

	quote! {
		impl #ident {
			pub(crate) fn from_repr(discriminant: usize) -> Option<Self> {
				#(#constants)*
				match discriminant {
					#(#cases)*
					_ => None,
				}
			}
		}
	}
}