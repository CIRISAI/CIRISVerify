//! The import-allowlist gate (FSD §4.1.1, §4.1.4).
//!
//! A node module's import section may name only the `ciris:node/*`
//! interfaces its world imports. The allowlist is derived from the WIT
//! with `wit-parser`, not hard-coded: every `(module, field)` pair is the
//! canonical-ABI name wit-bindgen gives an imported function, method or
//! resource drop of that world. Anything else, any non-function import
//! (memory, table, global, tag), and any import outside `ciris:node/`
//! is an offender.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use wasmparser::{Parser, Payload, TypeRef};
use wit_parser::{
    LiftLowerAbi, ManglingAndAbi, Resolve, ResourceIntrinsic, TypeDefKind, WasmImport, WorldItem,
};

/// The package every allowed import belongs to.
pub const PACKAGE_PREFIX: &str = "ciris:node/";

/// One import of the module.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Import {
    /// Core wasm import module.
    pub module: String,
    /// Core wasm import field.
    pub field: String,
    /// `func`, `memory`, `table`, `global` or `tag`.
    pub kind: &'static str,
}

impl fmt::Display for Import {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {:?} {:?}", self.kind, self.module, self.field)
    }
}

/// Why an import is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Offence {
    /// The module is not an interface this world imports from `ciris:node`.
    ModuleNotAllowed,
    /// The module is allowed but the WIT declares no such function.
    FieldNotDeclared,
    /// Only functions may be imported.
    NotAFunction,
}

impl fmt::Display for Offence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ModuleNotAllowed => "module is not a ciris:node interface of this world",
            Self::FieldNotDeclared => "field is not declared by the WIT",
            Self::NotAFunction => "only function imports are allowed",
        })
    }
}

/// The gate's verdict on one module.
#[derive(Clone, Debug)]
pub struct Report {
    /// Every import, in module order.
    pub imports: Vec<Import>,
    /// The refused imports.
    pub offenders: Vec<(Import, Offence)>,
}

impl Report {
    /// Whether the module passes.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.offenders.is_empty()
    }
}

/// The `(module, field)` pairs a world may import.
#[derive(Clone, Debug)]
pub struct Allowlist {
    /// The world the list was derived for.
    pub world: String,
    modules: BTreeSet<String>,
    pairs: BTreeSet<(String, String)>,
}

impl Allowlist {
    /// Derive the allowlist of `world` from WIT source text.
    ///
    /// # Errors
    /// The WIT does not parse, the world does not exist, or the world
    /// imports an interface outside `ciris:node`.
    pub fn from_wit_str(wit: &str, world: &str) -> Result<Self, String> {
        let mut resolve = Resolve::default();
        let pkg = resolve
            .push_str("ciris-node.wit", wit)
            .map_err(|e| format!("WIT does not parse: {e:#}"))?;
        Self::from_resolve(&resolve, pkg, world)
    }

    /// Derive the allowlist of `world` from a WIT file or directory.
    ///
    /// # Errors
    /// As [`Allowlist::from_wit_str`], or the path cannot be read.
    pub fn from_wit_path(path: &Path, world: &str) -> Result<Self, String> {
        let mut resolve = Resolve::default();
        let (pkg, _) = resolve
            .push_path(path)
            .map_err(|e| format!("WIT at {} does not parse: {e:#}", path.display()))?;
        Self::from_resolve(&resolve, pkg, world)
    }

    fn from_resolve(
        resolve: &Resolve,
        pkg: wit_parser::PackageId,
        world: &str,
    ) -> Result<Self, String> {
        let world_id = resolve
            .select_world(&[pkg], Some(world))
            .map_err(|e| format!("no world {world:?}: {e:#}"))?;
        let w = &resolve.worlds[world_id];
        let mangling = ManglingAndAbi::Legacy(LiftLowerAbi::Sync);
        let mut modules = BTreeSet::new();
        let mut pairs = BTreeSet::new();

        let mut add = |(module, field): (String, String)| {
            modules.insert(module.clone());
            pairs.insert((module, field));
        };

        for (key, item) in &w.imports {
            match item {
                WorldItem::Interface { id, .. } => {
                    let iface = &resolve.interfaces[*id];
                    for func in iface.functions.values() {
                        add(resolve.wasm_import_name(
                            mangling,
                            WasmImport::Func {
                                interface: Some(key),
                                func,
                            },
                        ));
                    }
                    for ty in iface.types.values() {
                        if matches!(resolve.types[*ty].kind, TypeDefKind::Resource) {
                            add(resolve.wasm_import_name(
                                mangling,
                                WasmImport::ResourceIntrinsic {
                                    interface: Some(key),
                                    resource: *ty,
                                    intrinsic: ResourceIntrinsic::ImportedDrop,
                                },
                            ));
                        }
                    }
                },
                WorldItem::Function(func) => add(resolve.wasm_import_name(
                    mangling,
                    WasmImport::Func {
                        interface: None,
                        func,
                    },
                )),
                WorldItem::Type(_) => {},
            }
        }
        // An exported resource is managed through `[export]…` imports.
        for (key, item) in &w.exports {
            if let WorldItem::Interface { id, .. } = item {
                for ty in resolve.interfaces[*id].types.values() {
                    if matches!(resolve.types[*ty].kind, TypeDefKind::Resource) {
                        for intrinsic in [
                            ResourceIntrinsic::ExportedDrop,
                            ResourceIntrinsic::ExportedNew,
                            ResourceIntrinsic::ExportedRep,
                        ] {
                            add(resolve.wasm_import_name(
                                mangling,
                                WasmImport::ResourceIntrinsic {
                                    interface: Some(key),
                                    resource: *ty,
                                    intrinsic,
                                },
                            ));
                        }
                    }
                }
            }
        }

        if let Some(m) = modules
            .iter()
            .find(|m| !m.trim_start_matches("[export]").starts_with(PACKAGE_PREFIX))
        {
            return Err(format!(
                "world {world:?} imports {m:?}, which is outside {PACKAGE_PREFIX}*"
            ));
        }
        Ok(Self {
            world: world.to_owned(),
            modules,
            pairs,
        })
    }

    /// The allowed import modules.
    pub fn modules(&self) -> impl Iterator<Item = &str> {
        self.modules.iter().map(String::as_str)
    }

    /// Check one import.
    #[must_use]
    pub fn check(&self, import: &Import) -> Option<Offence> {
        if !import.module.starts_with(PACKAGE_PREFIX) || !self.modules.contains(&import.module) {
            return Some(Offence::ModuleNotAllowed);
        }
        if import.kind != "func" {
            return Some(Offence::NotAFunction);
        }
        if !self
            .pairs
            .contains(&(import.module.clone(), import.field.clone()))
        {
            return Some(Offence::FieldNotDeclared);
        }
        None
    }

    /// Gate a module's bytes.
    ///
    /// # Errors
    /// The bytes are not a valid wasm module.
    pub fn gate(&self, wasm: &[u8]) -> Result<Report, String> {
        let imports = imports_of(wasm)?;
        let offenders = imports
            .iter()
            .filter_map(|i| self.check(i).map(|o| (i.clone(), o)))
            .collect();
        Ok(Report { imports, offenders })
    }
}

/// The imports of a core wasm module.
///
/// # Errors
/// The bytes are not a valid wasm module, or are a component.
pub fn imports_of(wasm: &[u8]) -> Result<Vec<Import>, String> {
    let mut out = Vec::new();
    for payload in Parser::new(0).parse_all(wasm) {
        match payload.map_err(|e| format!("not a wasm module: {e}"))? {
            Payload::Version { encoding, .. } if encoding != wasmparser::Encoding::Module => {
                return Err("a component, not a core module (FSD §4.2)".to_owned());
            },
            Payload::ImportSection(reader) => {
                for imp in reader.into_imports() {
                    let imp = imp.map_err(|e| format!("bad import section: {e}"))?;
                    let kind = match imp.ty {
                        TypeRef::Func(_) | TypeRef::FuncExact(_) => "func",
                        TypeRef::Memory(_) => "memory",
                        TypeRef::Table(_) => "table",
                        TypeRef::Global(_) => "global",
                        TypeRef::Tag(_) => "tag",
                    };
                    out.push(Import {
                        module: imp.module.to_owned(),
                        field: imp.name.to_owned(),
                        kind,
                    });
                }
            },
            _ => {},
        }
    }
    Ok(out)
}
