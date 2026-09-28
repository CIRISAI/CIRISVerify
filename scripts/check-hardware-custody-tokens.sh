#!/usr/bin/env bash
# CIRISVerify#296 — every `hardware_custody:{platform}:{version}` dimension this
# crate can emit must be ACCEPTED by CIRISConstitution's own namespace matcher.
#
# Why a script and not only a Rust test: the authority is CC's matcher, not our
# reading of its registry JSON. Reading the JSON is what produced the wrong
# conclusion during #296 triage — `hardware_custody:{platform}` has no
# `{version}` segment in its own `segments` array, yet R3's version grammar is
# GLOBAL and the matcher requires the tail. Only running the matcher settles it.
#
# Skips (exit 0) when CIRISConstitution is not checked out beside this repo, so
# CI without the sibling stays green; the Rust test
# `every_hardware_type_maps_to_a_registered_platform_token` is the always-on half.
set -euo pipefail

CC="${CIRIS_CONSTITUTION_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/CIRISConstitution}"
MATCHER="$CC/tools/cc_namespace_match.py"

if [[ ! -f "$MATCHER" ]]; then
  echo "SKIP: CC matcher not found at $MATCHER (set CIRIS_CONSTITUTION_DIR)"
  exit 0
fi

# The tokens come from the one source of truth, not a second hand-written list.
TOKENS=$(grep -A 40 'pub const ALL_PLATFORMS' src/ciris-keyring/src/types.rs \
         | grep -oE '"[a-z_]+"' | tr -d '"' | sed '/^$/d')
if [[ -z "$TOKENS" ]]; then
  echo "FAIL: could not read ALL_PLATFORMS from src/ciris-keyring/src/types.rs"
  exit 1
fi

VERSION=$(grep -oE 'HARDWARE_CUSTODY_VERSION: &str = "v[0-9]+"' \
          src/ciris-verify-core/src/federation_provenance.rs | grep -oE 'v[0-9]+')
if [[ -z "$VERSION" ]]; then
  echo "FAIL: could not read HARDWARE_CUSTODY_VERSION"
  exit 1
fi

DIMS=()
while read -r tok; do DIMS+=("hardware_custody:${tok}:${VERSION}"); done <<< "$TOKENS"

echo "replaying ${#DIMS[@]} dimensions through $MATCHER"
OUT=$(cd "$CC" && python3 "$MATCHER" "${DIMS[@]}")
echo "$OUT"

if grep -qv 'refusal=None' <<< "$OUT"; then
  echo
  echo "FAIL: at least one emitted dimension is REFUSED by the CC matcher:"
  grep -v 'refusal=None' <<< "$OUT"
  exit 1
fi

# Negative control: the pre-18.0.0 forms MUST still be refused, or the matcher
# is not actually gating anything.
BAD=("hardware_custody:android" "hardware_custody:tpm" "hardware_custody:tpmfirmware" \
     "hardware_custody:software_fallback" "hardware_custody:android_strongbox")
BADOUT=$(cd "$CC" && python3 "$MATCHER" "${BAD[@]}")
if grep -q 'refusal=None' <<< "$BADOUT"; then
  echo
  echo "FAIL: a known-bad dimension was ACCEPTED — the check proves nothing:"
  grep 'refusal=None' <<< "$BADOUT"
  exit 1
fi

# The wheel's `HardwareType` is a SECOND copy of this vocabulary, so it can drift
# from Rust's — and did: the first cut of #296's Python half invented security
# levels of 4 for the HSMs where Rust says 5, which would have made the same
# hardware yield different tier decisions per language (Codex P2 on PR #298).
# Both the token set and the security levels are compared here.
python3 - <<'PYEOF'
import pathlib, re

# Both sides are read as TEXT, deliberately. An earlier cut imported the wheel
# module instead, and a stale `__pycache__` made this check report a mismatch
# that no longer existed — which means it could equally have validated stale
# values and reported a false PASS. A guard that can silently stop guarding is
# the exact class this repo keeps removing, so neither side is imported.
rs = pathlib.Path("src/ciris-keyring/src/types.rs").read_text()
py = pathlib.Path("bindings/python/ciris_verify/types.py").read_text()

tokens_rs = set(re.findall(r'"([a-z_]+)"', rs[rs.index("ALL_PLATFORMS"):].split("];")[0]))

py_enum = py[py.index("class HardwareType(str, Enum):"):]
py_enum_body = py_enum[: py_enum.index("def supports_professional_license")]
tokens_py = dict(re.findall(r"^\s*([A-Z0-9_]+)\s*=\s*\"([a-z_]+)\"", py_enum_body, re.M))

if tokens_rs != set(tokens_py.values()):
    print("FAIL: token sets differ between Rust and Python")
    print("  only in Rust  :", sorted(tokens_rs - set(tokens_py.values())))
    print("  only in Python:", sorted(set(tokens_py.values()) - tokens_rs))
    raise SystemExit(1)

def levels_from(body, pattern, strip):
    out = {}
    for line in body.splitlines():
        m = re.match(pattern, line)
        if not m:
            continue
        for v in m.group(1).split("|"):
            out[v.strip().replace(strip, "")] = int(m.group(2))
    return out

rs_body = rs[rs.index("pub const fn security_level"):]
rs_body = rs_body[: rs_body.index("\n    }\n")]
rust_levels = levels_from(rs_body, r"\s*(Self::[A-Za-z0-9_ |:]+)\s*=>\s*(\d+),", "Self::")

py_body = py[py.index("def security_level"):]
py_body = py_body[: py_body.index("return levels.get")]
py_levels = {m.group(1): int(m.group(2)) for m in
             re.finditer(r"HardwareType\.([A-Z0-9_]+):\s*(\d+)", py_body)}

def variant(token):
    special = {"mac_os_secure_enclave": "MacOsSecureEnclave", "intel_sgx": "IntelSgx",
               "ios_secure_enclave": "IosSecureEnclave", "aws_cloud_hsm": "AwsCloudHsm",
               "gcp_cloud_hsm": "GcpCloudHsm", "yubi_hsm": "YubiHsm",
               "azure_hsm": "AzureHsm", "android_strongbox": "AndroidStrongbox"}
    return special.get(token, "".join(p.capitalize() for p in token.split("_")))

bad = []
for name, token in sorted(tokens_py.items()):
    r, pv = rust_levels.get(variant(token)), py_levels.get(name)
    if r is None or pv is None or r != pv:
        bad.append((token, pv, r))
if bad:
    print("FAIL: security_level differs between Rust and Python (token, python, rust):")
    for row in bad:
        print("  ", row)
    raise SystemExit(1)
print(f"Rust/Python vocabulary agrees: {len(tokens_py)} tokens, {len(py_levels)} security levels")
PYEOF

echo
echo "hardware_custody tokens: ${#DIMS[@]} accepted, ${#BAD[@]} known-bad forms still refused ✓"
