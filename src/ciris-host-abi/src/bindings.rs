//! wit-bindgen output for `wit/ciris-node.wit`, generated on every target.
//!
//! Types are shared by the wasm and native paths. The import stubs are
//! only callable on wasm32; on native the wrappers route to the installed
//! [`crate::host::Host`] instead, so nothing here is called there.
#![allow(
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    unsafe_code
)]

wit_bindgen::generate!({
    world: "node",
    path: "wit",
    additional_derives: [PartialEq, Eq],
    pub_export_macro: true,
    export_macro_name: "__export_node_world",
    default_bindings_module: "ciris_host_abi::bindings",
});

/// wit-bindgen output for the `vault` world (§8.5), sharing the `types`
/// interface with the node bindings. Item 9 implements its `signer`
/// export with the generated `export_vault!` macro.
pub mod vault {
    wit_bindgen::generate!({
        world: "vault",
        path: "wit",
        additional_derives: [PartialEq, Eq],
        with: {
            "ciris:node/types@0.1.0": crate::bindings::ciris::node::types,
            "ciris:node/log@0.1.0": crate::bindings::ciris::node::log,
        },
        pub_export_macro: true,
        export_macro_name: "export_vault",
        default_bindings_module: "ciris_host_abi::bindings::vault",
    });
}
