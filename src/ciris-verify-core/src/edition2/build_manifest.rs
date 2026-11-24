//! The build-manifest blob, `ciris-binary-manifest/1` (FSD-008 §6; accepted by
//! CIRISConstitution 2026-11-22 for CC 3.1.2.1, its CDDL
//! `tests/vectors/edition2/build_manifest/binary_manifest_v1.cddl`, vendored by CC
//! as `manifests/binary_manifest_v1.cddl`).
//!
//! One blob per (project, version, target) carries the binary hash and the
//! function table of one final shipped file, so the one build row that cites
//! it by digest covers both. The blob is **not** a signed object: it has no
//! `typ`, no key and no signature. It is the deterministic encoding of CC
//! 2.6.1.2 ([`crate::cde`]), no floats, and it carries nothing about the run:
//! it is a pure function of (file, project, version, target, tool), so two
//! producers given the same final file emit the same bytes, and anyone can
//! recompute the row's `manifest_hash` from the binary. `tool` names the
//! generator and its version and nothing else (no host, path, time or build
//! id), so it is constant for a release.
//!
//! ```text
//! { "format": "ciris-binary-manifest/1", "project": tstr, "version": tstr, "target": tstr,
//!   "binary_hash": bstr .size 32, "functions_root": bstr .size 32,
//!   ? "functions": { + name => { "offset": uint, "size": uint, "hash": bstr .size 32 } },
//!   "tool": tstr }
//! ```
//!
//! Every hash in the blob is a plain 32-byte SHA-256 (`bstr .size 32`, no
//! `[-16, digest]` wrapper): the format string pins SHA-256 for version 1.
//!
//! `project`, `version` and `target` are text exactly as given, compared byte
//! for byte with the citing row's `build.project`, `build.version` and its
//! dimension's `{target}`. A row whose descriptor differs from its blob's is
//! `build_manifest_descriptor_mismatch`, the token a size or hash mismatch
//! between row and blob also takes; that row-side check is not in this module.
//!
//! This module is the codec and the function-table Merkle root only. It reads
//! no row, no grant and no standing; it does not compare anything against the
//! running module.
//!
//! # Member order
//!
//! The FSD lists `format` first. CDE orders map keys by the bytewise order of
//! their encodings, which puts the shorter key `"tool"` before `"format"`, so
//! `format` cannot be the first member on the wire. [`decode`] reads and
//! checks `format` before any other member instead: a blob of another format
//! is refused as [`BlobError::WrongFormat`], never as an unknown member.
//!
//! # The function table and its root
//!
//! [`functions_root`] is a Merkle tree of one leaf per function, the locale
//! tree's construction: CC 3.1.2.1, the paragraphs beginning "A locale
//! manifest is a Merkle tree of one leaf per locale" and "Locale ordering:
//! … Padding: repeat the last leaf to the next power of two". The tree alone,
//! over leaf byte strings in a caller's order, is [`merkle_leaf_hash`] and
//! [`merkle_root`]; CC has no known answers for it, so the generic
//! `merkle_tree` section of `binary_manifest_v1_vectors.json` is the shared
//! set for locale manifests and function tables. For a function table:
//!
//! - one leaf per function, the leaves in the **byte order of the function
//!   names** (not the CDE key order of the inline map, which is length first:
//!   `"b"` precedes `"aa"` on the wire, `"aa"` precedes `"b"` in the tree);
//! - a leaf is `CDE({"name", "offset", "size", "hash"})` ([`leaf_bytes`]),
//!   hashed `SHA-256(0x00 ‖ leaf)` (the RFC 6962 leaf prefix);
//! - a parent is `SHA-256(0x01 ‖ left ‖ right)`;
//! - a non-power-of-two count is padded by repeating the last leaf to the next
//!   power of two ("not RFC 6962's split, and not the per-level duplication of
//!   CC 6.1.1"). One leaf is its own root.
//!
//! A table of zero functions is refused. When `functions` is inline,
//! [`decode`] recomputes the root and refuses a difference
//! ([`BlobError::FunctionsRootMismatch`], `build_manifest_functions_root_mismatch`).
//!
//! # What `offset` is relative to
//!
//! An offset is relative to the base the runtime resolves for the image that
//! holds the code (FSD-008 Q16, decided by verify): no `text_section_offset`
//! or other metadata member is carried. As `ciris-manifest-tool` computes it
//! and `security::function_integrity::verify_functions` reads it:
//!
//! - **ELF** (Linux, Android): `st_value − p_vaddr`, the symbol's virtual
//!   address less the virtual address of the executable (`PF_X`) `PT_LOAD`
//!   segment that contains `.text`. The Linux runtime resolves that base as
//!   `dlpi_addr + p_vaddr` of the object holding verify's code. The Android
//!   runtime today resolves `exec mapping start + (text_section_offset −
//!   maps_file_offset)`, which is `load bias + .text vaddr`: the same base
//!   only when `.text` begins its segment (the layout lld emits). Without
//!   `text_section_offset` the Android runtime has to resolve the segment
//!   base as Linux does; that change goes with `verify_functions`, not here.
//! - **Mach-O** (macOS, iOS): `n_value − vmaddr` of the `__TEXT` segment. The
//!   runtime base is the image's Mach-O header (`dladdr`'s `dli_fbase`), which
//!   is where `__TEXT` (file offset 0) is mapped. For a fat file the tool
//!   reads the first slice.
//! - **PE** (Windows): the export's RVA, relative to the image base. The
//!   runtime base is the module handle (`GetModuleHandleExW(FROM_ADDRESS)`).
//!
//! A function's `hash` is SHA-256 of its `size` bytes at that offset in the
//! file as mapped, 32 bytes, as `binary_hash` is.
//! `binary_hash` is [`crate::binary_format::canonical_binary_hash`] of the
//! final file (the whole file; the page-aligned `__TEXT` region on Mach-O).
//!
//! Pure: no clock, no randomness, no I/O.

#[allow(unused_imports)]
use crate::prelude::*;

use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;

use crate::cde::{self, CdeError, Value};

/// The `format` member's one value.
pub const FORMAT: &str = "ciris-binary-manifest/1";
/// The largest blob [`decode`] reads (1 MiB), checked before decoding. A
/// table of 96 `ciris_verify_*` functions encodes in about 15 KB.
pub const MAX_BLOB_LEN: usize = 1 << 20;
/// The longest `project` and `version` (FSD-008 §4.4, the build row's rule).
pub const MAX_DESCRIPTOR_LEN: usize = 64;
/// The longest `target` (verify's bound; the FSD gives none).
pub const MAX_TARGET_LEN: usize = 64;
/// The longest function name (verify's bound; the FSD gives none).
pub const MAX_NAME_LEN: usize = 1024;
/// The longest `tool` (verify's bound; the FSD gives none).
pub const MAX_TOOL_LEN: usize = 128;
/// The RFC 6962 leaf prefix.
pub const LEAF_PREFIX: u8 = 0x00;
/// The RFC 6962 node prefix.
pub const NODE_PREFIX: u8 = 0x01;

/// The blob's members, closed.
pub const MEMBERS: [&str; 8] = [
    "format",
    "project",
    "version",
    "target",
    "binary_hash",
    "functions_root",
    "functions",
    "tool",
];
/// The members a blob must carry (every one but `functions`).
pub const REQUIRED_MEMBERS: [&str; 7] = [
    "format",
    "project",
    "version",
    "target",
    "binary_hash",
    "functions_root",
    "tool",
];
/// The members of one function entry, closed and all required.
pub const ENTRY_MEMBERS: [&str; 3] = ["offset", "size", "hash"];

/// One function of the table: one Merkle leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionLeaf {
    /// The symbol name (the inline map's key).
    pub name: String,
    /// The offset from the runtime base (module docs).
    pub offset: u64,
    /// The function's length in bytes.
    pub size: u64,
    /// SHA-256 of the function's bytes.
    pub hash: [u8; 32],
}

/// A decoded `ciris-binary-manifest/1` blob. `project`, `version` and
/// `target` are text exactly as encoded (no normalisation), so they compare
/// byte for byte with the build row's `build.project` / `build.version` and
/// its dimension's `{target}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryManifest {
    /// The project, `[a-z0-9-]`, 1..=64 bytes.
    pub project: String,
    /// The version, 1..=64 bytes, compared byte for byte.
    pub version: String,
    /// The target triple.
    pub target: String,
    /// `canonical_binary_hash` of the final file.
    pub binary_hash: [u8; 32],
    /// The root over the function table ([`functions_root`]).
    pub functions_root: [u8; 32],
    /// The inline table, in the byte order of the names, when carried.
    pub functions: Option<Vec<FunctionLeaf>>,
    /// The generator and its version, e.g. `ciris-manifest-tool/23.6.0`, and
    /// nothing about the run.
    pub tool: String,
}

/// Why a blob is refused. Each has a stable [`token`](BlobError::token).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlobError {
    /// Longer than [`MAX_BLOB_LEN`]; refused before decoding.
    Oversize,
    /// Not the deterministic encoding of one item (CC 2.6.1.2).
    NotDeterministic(CdeError),
    /// A floating-point value.
    Float,
    /// The top level is not a map.
    NotAMap,
    /// `format` is not [`FORMAT`].
    WrongFormat,
    /// A member the blob (or a function entry) does not admit.
    UnknownMember {
        /// `blob` or `function`.
        within: &'static str,
    },
    /// A required member is absent.
    MissingMember {
        /// The member.
        member: &'static str,
    },
    /// A member of the wrong type or out of its range.
    Malformed {
        /// The member.
        member: &'static str,
    },
    /// A function table of zero functions.
    EmptyFunctions,
    /// Two leaves of one name (a producer's table; a decoded map cannot
    /// repeat a key).
    DuplicateFunction,
    /// The inline table's root is not `functions_root`.
    FunctionsRootMismatch,
}

impl BlobError {
    /// The stable refusal token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Oversize => "build_manifest_oversize",
            Self::NotDeterministic(_) => "build_manifest_not_deterministic",
            Self::Float => "build_manifest_float",
            Self::NotAMap => "build_manifest_not_a_map",
            Self::WrongFormat => "build_manifest_wrong_format",
            Self::UnknownMember { .. } => "build_manifest_unknown_member",
            Self::MissingMember { .. } => "build_manifest_missing_member",
            Self::Malformed { .. } => "build_manifest_malformed",
            Self::EmptyFunctions => "build_manifest_empty_functions",
            Self::DuplicateFunction => "build_manifest_duplicate_function",
            Self::FunctionsRootMismatch => "build_manifest_functions_root_mismatch",
        }
    }

    /// The member or place the refusal names, where it names one.
    #[must_use]
    pub fn detail(self) -> Option<&'static str> {
        match self {
            Self::UnknownMember { within } => Some(within),
            Self::MissingMember { member } | Self::Malformed { member } => Some(member),
            _ => None,
        }
    }
}

impl core::fmt::Display for BlobError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.detail() {
            Some(d) => write!(f, "{}: {d}", self.token()),
            None => f.write_str(self.token()),
        }
    }
}

fn bytes32(v: Option<&Value>, member: &'static str) -> Result<[u8; 32], BlobError> {
    v.ok_or(BlobError::MissingMember { member })?
        .as_bytes()
        .and_then(|b| b.try_into().ok())
        .ok_or(BlobError::Malformed { member })
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

/// The leaf's deterministic encoding, `CDE({name, offset, size, hash})`.
#[must_use]
pub fn leaf_bytes(leaf: &FunctionLeaf) -> Vec<u8> {
    cde::encode(&Value::Map(vec![
        (text("name"), text(&leaf.name)),
        (text("offset"), Value::Uint(leaf.offset)),
        (text("size"), Value::Uint(leaf.size)),
        (text("hash"), Value::Bytes(leaf.hash.to_vec())),
    ]))
}

/// `SHA-256(0x00 ‖ leaf_bytes(leaf))`.
#[must_use]
pub fn leaf_hash(leaf: &FunctionLeaf) -> [u8; 32] {
    merkle_leaf_hash(&leaf_bytes(leaf))
}

/// The tree's leaf hash over any leaf byte string, `SHA-256(0x00 ‖ leaf)`.
#[must_use]
pub fn merkle_leaf_hash(leaf: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([LEAF_PREFIX]);
    h.update(leaf);
    h.finalize().into()
}

/// The CC 3.1.2.1 tree's root over leaf byte strings in the order given
/// (each use orders its own leaves): each leaf hashed [`merkle_leaf_hash`],
/// padded by repeating the last leaf to the next power of two, parents
/// `SHA-256(0x01 ‖ left ‖ right)`. One leaf's hash is its own root; zero
/// leaves give `SHA-256("")` (RFC 6962's empty tree), which no use of this
/// module accepts.
#[must_use]
pub fn merkle_root(leaves: &[&[u8]]) -> [u8; 32] {
    let hashes: Vec<[u8; 32]> = leaves.iter().map(|l| merkle_leaf_hash(l)).collect();
    root_of_hashes(&hashes)
}

fn root_of_hashes(leaf_hashes: &[[u8; 32]]) -> [u8; 32] {
    let Some(&last) = leaf_hashes.last() else {
        return Sha256::digest([]).into();
    };
    let mut layer = leaf_hashes.to_vec();
    layer.resize(layer.len().next_power_of_two(), last);
    while layer.len() > 1 {
        layer = layer
            .chunks_exact(2)
            .map(|p| node_hash(&p[0], &p[1]))
            .collect();
    }
    layer[0]
}

fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([NODE_PREFIX]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// The Merkle root over `leaves` (module docs): sorted into the byte order of
/// their names here, whatever order they are given in, padded by repeating
/// the last leaf to the next power of two.
///
/// Zero leaves give `SHA-256("")` (RFC 6962's empty tree) so the function is
/// total, but a table of zero functions is refused by [`decode`],
/// [`encode`] and [`check_functions_root`]. Names are not checked for
/// repeats here; [`check_functions_root`] refuses them.
#[must_use]
pub fn functions_root(leaves: &[FunctionLeaf]) -> [u8; 32] {
    let mut sorted: Vec<&FunctionLeaf> = leaves.iter().collect();
    sorted.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    let leaves: Vec<Vec<u8>> = sorted.into_iter().map(leaf_bytes).collect();
    let refs: Vec<&[u8]> = leaves.iter().map(Vec::as_slice).collect();
    merkle_root(&refs)
}

/// Check a function table against a `functions_root`: at least one function,
/// no name twice, and the recomputed root equal (in constant time). For the
/// inline table [`decode`] calls this itself.
///
/// # Errors
///
/// [`BlobError::EmptyFunctions`], [`BlobError::DuplicateFunction`] or
/// [`BlobError::FunctionsRootMismatch`].
pub fn check_functions_root(leaves: &[FunctionLeaf], root: &[u8; 32]) -> Result<(), BlobError> {
    if leaves.is_empty() {
        return Err(BlobError::EmptyFunctions);
    }
    let mut names: Vec<&[u8]> = leaves.iter().map(|l| l.name.as_bytes()).collect();
    names.sort_unstable();
    if names.windows(2).any(|w| w[0] == w[1]) {
        return Err(BlobError::DuplicateFunction);
    }
    if bool::from(functions_root(leaves).ct_eq(root)) {
        Ok(())
    } else {
        Err(BlobError::FunctionsRootMismatch)
    }
}

fn check_project(s: &str) -> bool {
    (1..=MAX_DESCRIPTOR_LEN).contains(&s.len())
        && s.bytes()
            .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

fn check_len(s: &str, max: usize) -> bool {
    (1..=max).contains(&s.len())
}

fn check_target(s: &str) -> bool {
    check_len(s, MAX_TARGET_LEN) && s.bytes().all(|c| (0x21..=0x7e).contains(&c))
}

impl BinaryManifest {
    /// Assemble a blob over `functions`: sorts them into the byte order of
    /// their names, computes `functions_root`, and carries the table inline
    /// when `inline`. Every member is checked as [`decode`] checks it.
    ///
    /// # Errors
    ///
    /// The [`BlobError`] [`decode`] would refuse the result with.
    pub fn new(
        project: &str,
        version: &str,
        target: &str,
        binary_hash: [u8; 32],
        mut functions: Vec<FunctionLeaf>,
        inline: bool,
        tool: &str,
    ) -> Result<Self, BlobError> {
        functions.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        let functions_root = functions_root(&functions);
        check_functions_root(&functions, &functions_root)?;
        let m = Self {
            project: project.to_owned(),
            version: version.to_owned(),
            target: target.to_owned(),
            binary_hash,
            functions_root,
            functions: inline.then_some(functions),
            tool: tool.to_owned(),
        };
        m.check_members()?;
        Ok(m)
    }

    fn check_members(&self) -> Result<(), BlobError> {
        let bad = |member| Err(BlobError::Malformed { member });
        if !check_project(&self.project) {
            return bad("project");
        }
        if !check_len(&self.version, MAX_DESCRIPTOR_LEN) {
            return bad("version");
        }
        if !check_target(&self.target) {
            return bad("target");
        }
        if !check_len(&self.tool, MAX_TOOL_LEN) {
            return bad("tool");
        }
        if let Some(fs) = &self.functions {
            for f in fs {
                if !check_len(&f.name, MAX_NAME_LEN) {
                    return bad("functions");
                }
            }
            check_functions_root(fs, &self.functions_root)?;
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        let mut m = vec![
            (text("format"), text(FORMAT)),
            (text("project"), text(&self.project)),
            (text("version"), text(&self.version)),
            (text("target"), text(&self.target)),
            (text("binary_hash"), Value::Bytes(self.binary_hash.to_vec())),
            (
                text("functions_root"),
                Value::Bytes(self.functions_root.to_vec()),
            ),
            (text("tool"), text(&self.tool)),
        ];
        if let Some(fs) = &self.functions {
            let table = fs
                .iter()
                .map(|f| {
                    (
                        text(&f.name),
                        Value::Map(vec![
                            (text("offset"), Value::Uint(f.offset)),
                            (text("size"), Value::Uint(f.size)),
                            (text("hash"), Value::Bytes(f.hash.to_vec())),
                        ]),
                    )
                })
                .collect();
            m.push((text("functions"), Value::Map(table)));
        }
        Value::Map(m)
    }
}

/// The blob's deterministic encoding. Refuses what [`decode`] would refuse,
/// so a producer cannot emit a blob a reader turns away.
///
/// # Errors
///
/// A member off its rule, a table off its root, or a result over
/// [`MAX_BLOB_LEN`].
pub fn encode(m: &BinaryManifest) -> Result<Vec<u8>, BlobError> {
    m.check_members()?;
    let bytes = cde::encode(&m.to_value());
    if bytes.len() > MAX_BLOB_LEN {
        return Err(BlobError::Oversize);
    }
    Ok(bytes)
}

fn get<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

fn req_text<'a>(map: &'a [(Value, Value)], member: &'static str) -> Result<&'a str, BlobError> {
    get(map, member)
        .ok_or(BlobError::MissingMember { member })?
        .as_text()
        .ok_or(BlobError::Malformed { member })
}

fn read_entry(name: &Value, entry: &Value) -> Result<FunctionLeaf, BlobError> {
    let bad = BlobError::Malformed {
        member: "functions",
    };
    let name = name.as_text().ok_or(bad)?;
    if !check_len(name, MAX_NAME_LEN) {
        return Err(bad);
    }
    let e = entry.as_map().ok_or(bad)?;
    if e.iter()
        .any(|(k, _)| !k.as_text().is_some_and(|k| ENTRY_MEMBERS.contains(&k)))
    {
        return Err(BlobError::UnknownMember { within: "function" });
    }
    let uint = |member: &'static str| match get(e, member) {
        None => Err(BlobError::MissingMember { member }),
        Some(Value::Uint(n)) => Ok(*n),
        Some(_) => Err(BlobError::Malformed { member }),
    };
    let offset = uint("offset")?;
    let size = uint("size")?;
    let hash = bytes32(get(e, "hash"), "hash")?;
    Ok(FunctionLeaf {
        name: name.to_owned(),
        offset,
        size,
        hash,
    })
}

/// Read a blob, strictly, in this order: the length against
/// [`MAX_BLOB_LEN`] (before decoding); the deterministic encoding (CC
/// 2.6.1.2: [`cde::decode`] admits one encoding of a value, so no re-encoding
/// is needed, and no float); a map; `format` first; the closed member set;
/// every required member; each member's type and range; and, when the table
/// is inline, its root ([`check_functions_root`]).
///
/// # Errors
///
/// The first [`BlobError`] met.
pub fn decode(bytes: &[u8]) -> Result<BinaryManifest, BlobError> {
    if bytes.len() > MAX_BLOB_LEN {
        return Err(BlobError::Oversize);
    }
    let v = cde::decode(bytes).map_err(|e| match e {
        CdeError::Float => BlobError::Float,
        e => BlobError::NotDeterministic(e),
    })?;
    let map = v.as_map().ok_or(BlobError::NotAMap)?;
    match get(map, "format") {
        None => {
            return Err(BlobError::MissingMember { member: "format" });
        },
        Some(f) if f.as_text() == Some(FORMAT) => {},
        Some(_) => return Err(BlobError::WrongFormat),
    }
    if map
        .iter()
        .any(|(k, _)| !k.as_text().is_some_and(|k| MEMBERS.contains(&k)))
    {
        return Err(BlobError::UnknownMember { within: "blob" });
    }
    for member in REQUIRED_MEMBERS {
        if get(map, member).is_none() {
            return Err(BlobError::MissingMember { member });
        }
    }
    let bad = |member| BlobError::Malformed { member };
    let project = req_text(map, "project")?;
    let version = req_text(map, "version")?;
    let target = req_text(map, "target")?;
    let binary_hash = bytes32(get(map, "binary_hash"), "binary_hash")?;
    let functions_root = bytes32(get(map, "functions_root"), "functions_root")?;
    let tool = req_text(map, "tool")?;
    let functions = match get(map, "functions") {
        None => None,
        Some(t) => {
            let t = t.as_map().ok_or(bad("functions"))?;
            if t.is_empty() {
                return Err(BlobError::EmptyFunctions);
            }
            let mut leaves = t
                .iter()
                .map(|(k, e)| read_entry(k, e))
                .collect::<Result<Vec<_>, _>>()?;
            leaves.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
            Some(leaves)
        },
    };
    let m = BinaryManifest {
        project: project.to_owned(),
        version: version.to_owned(),
        target: target.to_owned(),
        binary_hash,
        functions_root,
        functions,
        tool: tool.to_owned(),
    };
    m.check_members()?;
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(name: &str, n: u8) -> FunctionLeaf {
        FunctionLeaf {
            name: name.to_owned(),
            offset: u64::from(n) * 16,
            size: 16,
            hash: [n; 32],
        }
    }

    fn blob(fs: Vec<FunctionLeaf>, inline: bool) -> BinaryManifest {
        BinaryManifest::new(
            "ciris-verify",
            "23.6.0",
            "x86_64-unknown-linux-gnu",
            [7; 32],
            fs,
            inline,
            "ciris-manifest-tool/23.6.0",
        )
        .unwrap()
    }

    #[test]
    fn round_trip_inline_and_not() {
        for inline in [true, false] {
            let m = blob(vec![leaf("b", 2), leaf("aa", 1), leaf("c", 3)], inline);
            let bytes = encode(&m).unwrap();
            assert_eq!(decode(&bytes).unwrap(), m);
            assert_eq!(encode(&decode(&bytes).unwrap()).unwrap(), bytes);
        }
    }

    #[test]
    fn leaves_in_name_byte_order_not_cde_order() {
        let m = blob(vec![leaf("b", 2), leaf("aa", 1)], true);
        let names: Vec<_> = m.functions.unwrap().into_iter().map(|f| f.name).collect();
        assert_eq!(names, ["aa", "b"]);
        let r = functions_root(&[leaf("aa", 1), leaf("b", 2)]);
        assert_eq!(
            r,
            node_hash(&leaf_hash(&leaf("aa", 1)), &leaf_hash(&leaf("b", 2)))
        );
    }

    #[test]
    fn padding_repeats_last_leaf() {
        let ls = [leaf("a", 1), leaf("b", 2), leaf("c", 3)];
        let h: Vec<_> = ls.iter().map(leaf_hash).collect();
        let expect = node_hash(&node_hash(&h[0], &h[1]), &node_hash(&h[2], &h[2]));
        assert_eq!(functions_root(&ls), expect);
        assert_eq!(functions_root(&ls[..1]), h[0]);
    }

    #[test]
    fn root_mismatch_and_empty_and_duplicate() {
        let mut m = blob(vec![leaf("a", 1)], true);
        m.functions_root[0] ^= 1;
        assert_eq!(encode(&m), Err(BlobError::FunctionsRootMismatch));
        let mut m = blob(vec![leaf("a", 1)], true);
        m.functions.as_mut().unwrap()[0].hash = [9; 32];
        let bytes = cde::encode(&m.to_value());
        assert_eq!(decode(&bytes), Err(BlobError::FunctionsRootMismatch));
        assert_eq!(
            check_functions_root(&[], &[0; 32]),
            Err(BlobError::EmptyFunctions)
        );
        assert_eq!(
            check_functions_root(&[leaf("a", 1), leaf("a", 2)], &[0; 32]),
            Err(BlobError::DuplicateFunction)
        );
    }

    #[test]
    fn oversize_refused_before_decoding() {
        assert_eq!(
            decode(&vec![0xff; MAX_BLOB_LEN + 1]),
            Err(BlobError::Oversize)
        );
    }
}
