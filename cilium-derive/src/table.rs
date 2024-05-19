use syn::{Data, DeriveInput, Field, Path};
use quote::{format_ident, quote};
use proc_macro2::TokenStream;

pub fn derive(tokens: proc_macro::TokenStream) -> TokenStream {
	let DeriveInput {
		attrs,
		vis,
		ident,
		data,
		..
	} = syn::parse(tokens).unwrap();

	let data = match data {
		Data::Struct(data) => data,
		Data::Enum(_) => panic!("Enums are not supported"),
		Data::Union(_) => panic!("Unions are not supported"),
	};

	let table = format_ident!("{}Table", ident);
	let index = format_ident!("{}Index", ident);

	let mut print = None;
	let read_with = attrs.iter().find_map(|a| {
		let ident = a.path().get_ident()?;
		if ident == "print_rows" {
			print = Some(quote! {
				#[cfg(debug_assertions)]
				println!("{:X?}", row);
			});
		}
		if ident != "read_with" {
			return None;
		}
		Some(a.parse_args::<Path>().unwrap())
	});

	let read_impl = match read_with {
		Some(path) => quote! {
			#path(stream, idx_sizes, len)
		},
		None => {
			let reads = data.fields.iter().map(
				|Field { ty, ident, .. }| quote!(#ident: <#ty>::read(stream, idx_sizes.as_ref())?),
			);

			quote! {
				let mut rows = Vec::with_capacity(len);
				for i in 0..len {
					let row = #ident { #(#reads),* };
					#print
					rows.push(row)
				}
				Ok(Self { rows })
			}
		},
	};

	quote! {
		#[derive(Debug)]
		#vis struct #table {
			rows: Vec<#ident>,
		}

		impl #table {
			pub fn read(stream: &mut Cursor<&[u8]>, idx_sizes: &IndexSizes, len: usize) -> std::io::Result<Self> {
				#read_impl
			}
		}

		impl Table for #table {
			fn len(&self) -> usize {
				self.rows.len()
			}
			fn kind(&self) -> TableKind {
				TableKind::#ident
			}
		}

		#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
		pub struct #index(usize);

		impl FromByteStream for #index {
			type Deps = IndexSizes;
			fn read(stream: &mut Cursor<&[u8]>, deps: &Self::Deps) -> std::io::Result<Self> {
				let table_sizes: &TableIndexSizes = deps.as_ref();
				let table_size = table_sizes.0[TableKind::#ident as usize];
				let size = 2 + 2 * (table_size > 65536) as usize;
				let mut value = 0usize.to_ne_bytes();
				stream.read_exact(&mut value[..size])?;
				Ok(Self(usize::from_le_bytes(value)))
			}
		}
	}
}
