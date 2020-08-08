extern crate proc_macro;

use proc_macro::TokenStream;
use syn::{
    punctuated::Punctuated,
    token::{Comma, Paren},
    Field, Fields, FieldsUnnamed, ItemEnum, Type, Variant, Visibility,
};

#[proc_macro_attribute]
pub fn simplified(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let enum_item = syn::parse_macro_input!(item as ItemEnum);
    let mut expanded_enum = enum_item.clone();

    let mut variants: Punctuated<Variant, Comma> = Punctuated::new();
    for variant in enum_item.variants {
        let mut expanded_variant = variant.clone();

        if let Fields::Unit = variant.fields {
            let ident = variant.ident;
            let field = Field {
                attrs: vec![],
                vis: Visibility::Inherited,
                colon_token: None,
                ident: None,
                ty: Type::Verbatim(quote::quote! {#ident}),
            };

            let mut unnamed = Punctuated::new();
            unnamed.push(field);
            let expanded_fields = Fields::Unnamed(FieldsUnnamed {
                paren_token: Paren::default(),
                unnamed,
            });

            expanded_variant.fields = expanded_fields;
        };

        variants.push(expanded_variant);
    }

    expanded_enum.variants = variants;

    TokenStream::from(quote::quote! {
        #expanded_enum
    })
}
