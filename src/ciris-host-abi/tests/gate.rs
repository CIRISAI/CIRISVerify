//! The import-allowlist gate over hand-built modules.

use ciris_host_abi::gate::{imports_of, Allowlist, Offence};
use wasm_encoder::{EntityType, ImportSection, MemoryType, Module, TypeSection, ValType};

/// A core module importing `imports` (all `() -> i64` functions) plus,
/// optionally, a memory.
fn module(imports: &[(&str, &str)], memory: Option<(&str, &str)>) -> Vec<u8> {
    let mut types = TypeSection::new();
    types.ty().function([], [ValType::I64]);
    let mut section = ImportSection::new();
    for (m, f) in imports {
        section.import(m, f, EntityType::Function(0));
    }
    if let Some((m, f)) = memory {
        section.import(
            m,
            f,
            MemoryType {
                minimum: 1,
                maximum: None,
                memory64: false,
                shared: false,
                page_size_log2: None,
            },
        );
    }
    let mut module = Module::new();
    module.section(&types).section(&section);
    module.finish()
}

fn node() -> Allowlist {
    Allowlist::from_wit_str(ciris_host_abi::WIT, "node").expect("WIT parses")
}

#[test]
fn one_good_one_bad() {
    let wasm = module(
        &[("ciris:node/clock@0.1.0", "monotonic-us"), ("env", "now")],
        None,
    );
    let report = node().gate(&wasm).unwrap();
    assert_eq!(report.imports.len(), 2);
    assert!(!report.passed());
    assert_eq!(report.offenders.len(), 1);
    assert_eq!(report.offenders[0].0.module, "env");
    assert_eq!(report.offenders[0].1, Offence::ModuleNotAllowed);
}

#[test]
fn only_good_passes() {
    let wasm = module(
        &[
            ("ciris:node/clock@0.1.0", "monotonic-us"),
            ("ciris:node/random@0.1.0", "fill"),
            ("ciris:node/storage@0.1.0", "[method]volume.read"),
            ("ciris:node/storage@0.1.0", "[resource-drop]volume"),
            ("ciris:node/net@0.1.0", "[method]stream.info"),
            ("ciris:node/seal@0.1.0", "sign-composite"),
            ("ciris:node/seal@0.1.0", "generate"),
            ("ciris:node/seal@0.1.0", "kem-decap"),
            ("ciris:node/seal@0.1.0", "wrap"),
            ("ciris:node/seal@0.1.0", "unwrap"),
            ("ciris:node/net@0.1.0", "bind"),
            ("ciris:node/net@0.1.0", "can-datagram"),
            ("ciris:node/net@0.1.0", "can-multicast"),
            ("ciris:node/net@0.1.0", "interfaces"),
            ("ciris:node/net@0.1.0", "[method]datagram.send-to"),
            ("ciris:node/net@0.1.0", "[method]datagram.recv-from"),
            ("ciris:node/net@0.1.0", "[method]datagram.multicast-join"),
            ("ciris:node/net@0.1.0", "[resource-drop]datagram"),
        ],
        None,
    );
    let report = node().gate(&wasm).unwrap();
    assert!(report.passed(), "{:?}", report.offenders);
}

#[test]
fn provision_is_gone() {
    // Seeds never pass through node memory (§8.5): no node-facing provision.
    let wasm = module(&[("ciris:node/seal@0.1.0", "provision")], None);
    let report = node().gate(&wasm).unwrap();
    assert_eq!(report.offenders[0].1, Offence::FieldNotDeclared);
}

#[test]
fn forbidden_families_are_refused() {
    let wasm = module(
        &[
            ("wasi_snapshot_preview1", "random_get"),
            ("__wbindgen_placeholder__", "__wbindgen_describe"),
            ("wasi:random/random@0.2.0", "get-random-bytes"),
            ("ciris:node/clock@0.1.0", "sleep"),
            // `types` holds no functions, so it is never an import module.
            ("ciris:node/types@0.1.0", "errno"),
            // A real interface, but of the vault's world, not imported by node.
            ("ciris:node/signer@0.1.0", "sign-composite"),
        ],
        Some(("ciris:node/clock@0.1.0", "memory")),
    );
    let report = node().gate(&wasm).unwrap();
    let why: Vec<_> = report
        .offenders
        .iter()
        .map(|(i, o)| (i.field.as_str(), o.clone()))
        .collect();
    assert_eq!(
        why,
        vec![
            ("random_get", Offence::ModuleNotAllowed),
            ("__wbindgen_describe", Offence::ModuleNotAllowed),
            ("get-random-bytes", Offence::ModuleNotAllowed),
            ("sleep", Offence::FieldNotDeclared),
            ("errno", Offence::ModuleNotAllowed),
            ("sign-composite", Offence::ModuleNotAllowed),
            ("memory", Offence::NotAFunction),
        ]
    );
}

#[test]
fn allowlist_is_derived_per_world() {
    let node: Vec<_> = node().modules().map(str::to_owned).collect();
    assert_eq!(
        node,
        [
            "ciris:node/clock@0.1.0",
            "ciris:node/log@0.1.0",
            "ciris:node/net@0.1.0",
            "ciris:node/random@0.1.0",
            "ciris:node/seal@0.1.0",
            "ciris:node/storage@0.1.0",
            "ciris:node/wake@0.1.0",
        ]
    );
    let vault = Allowlist::from_wit_str(ciris_host_abi::WIT, "vault").unwrap();
    assert_eq!(
        vault.modules().collect::<Vec<_>>(),
        ["ciris:node/log@0.1.0", "ciris:node/random@0.1.0"]
    );
    // The vault imports random (for `signer.generate`), but no net or seal.
    let wasm = module(&[("ciris:node/random@0.1.0", "fill")], None);
    assert!(vault.gate(&wasm).unwrap().passed());
    let wasm = module(&[("ciris:node/net@0.1.0", "carriers")], None);
    assert!(!vault.gate(&wasm).unwrap().passed(), "the vault has no net");
}

#[test]
fn the_wit_file_on_disk_matches_the_compiled_copy() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("wit");
    let from_disk = Allowlist::from_wit_path(&dir, "node").unwrap();
    assert!(from_disk.modules().eq(node().modules()));
}

#[test]
fn not_wasm_is_an_error() {
    assert!(imports_of(b"not wasm").is_err());
}
