use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Field, Type};
use syn::parse::Parse;

pub fn derive(tokens: proc_macro::TokenStream) -> TokenStream {
    let DeriveInput {
        attrs,
        vis,
        ident,
        generics,
        data,
    } = syn::parse(tokens).unwrap();

    let data = match data {
        Data::Struct(data) => data,
        Data::Enum(_) => panic!("Enums are not supported"),
        Data::Union(_) => panic!("Unions are not supported"),
    };

    let table = format_ident!("{}Table", ident);
    let reads = data.fields.iter().map(
        |Field {
             attrs,
             vis,
             mutability,
             ident,
             colon_token,
             ty,
         } |match ty {
            Type::Path(path) => match path.path.get_ident() {
                Some(ty_ident) if ty_ident == "StringIndex" => quote! {
                   #ident: StringIndex::read(stream, string_idx_size)?
                },
                _ => quote!(#ident: <#ty>::read(stream)?)
            }
            _ => quote!(#ident: <#ty>::read(stream)?)
        },
    );

    quote! {
        #[derive(Debug)]
        #vis struct #table {
            row_size: usize,
            rows: Vec<#ident>,
        }

        impl #table {
            pub fn read(stream: &mut Cursor<&[u8]>, heap_sizes: u8, len: usize) -> std::io::Result<Self> {
                let start = stream.position() as usize;
                let blob_idx_size = 2 + 2 * ((heap_sizes & 0x4) != 0) as usize;
                let guid_idx_size = 2 + 2 * ((heap_sizes & 0x2) != 0) as usize;
                let string_idx_size = 2 + 2 * ((heap_sizes & 0x1) != 0) as usize;

                let mut rows = Vec::with_capacity(len);
                for _ in 0..len {
                    rows.push(#ident { #(#reads),* })
                }

                let row_size = (stream.position() as usize - start) / len;
                Ok(Self { rows, row_size })
            }
        }

        impl Table for #table {
			fn len(&self) -> usize {
				self.rows.len()
			}

            fn kind(&self) -> TableKind {
				TableKind::#ident
			}

			fn row_size(&self) -> usize {
				self.row_size
			}
		}
    }
}
