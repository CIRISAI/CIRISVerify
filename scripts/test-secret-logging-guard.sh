#!/usr/bin/env bash
# Self-test for check-no-secret-logging.sh (CIRISVerify#268).
#
# Six review rounds each found one more way to slip a secret past that guard —
# a `)` in a string, a `//` in a URL, a `)` in a comment, implicit capture,
# member access. Each was fixed as an instance. This is the matrix, so a
# future narrowing of the scanner fails here instead of silently un-catching a
# case someone already paid to find.
#
# A guard nobody tests is a guard that can stop guarding.
set -euo pipefail
cd "$(dirname "$0")/.."

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/src"
fail=0

check() { # label | body | expect(catch|pass)
    printf 'fn f() {\n    %b\n}\n' "$2" > "$TMP/src/probe.rs"
    if bash scripts/check-no-secret-logging.sh "$TMP/src" >/dev/null 2>&1; then
        got=pass
    else
        got=catch
    fi
    if [ "$got" != "$3" ]; then
        echo "  ✗ $1 — got $got, want $3" >&2
        fail=1
    fi
}

# MUST CATCH — every evasion form raised in review
check 'explicit field'        'tracing::info!(seed = %s, "x");'                      catch
check 'sigil shorthand'       'tracing::info!(?seed, "x");'                          catch
check 'positional'            'tracing::info!("s: {:?}", seed);'                     catch
check 'benign field alongside' 'tracing::info!(seed = %s, key_id = %k, "x");'        catch
check 'paren inside string'   'tracing::info!("seed bytes): {:?}", seed);'           catch
check 'inline capture'        'tracing::info!("seed={seed:?}");'                     catch
check 'member access'         'tracing::info!("pin={:?}", cfg.pin);'                 catch
check 'url with // inside'    'tracing::info!("https://x.invalid seed={:?}", seed);' catch
check 'paren in block comment' 'tracing::info!(/* note) */ seed = %s, "x");'          catch
check 'paren in line comment' 'tracing::info!(\n        // note)\n        seed = %s, "x");' catch

# #[instrument] records every arg unless skipped — the attribute IS the log
# statement, with no macro anywhere (#268 round 7)
check 'instrument records seed'  '#[instrument]\n    fn g(seed: &[u8]) {}'              catch
check 'instrument skip(seed)'    '#[instrument(skip(seed))]\n    fn g(seed: &[u8]) {}'  pass
check 'instrument skip_all'      '#[instrument(skip_all)]\n    fn g(seed: &[u8]) {}'    pass
# A u64 cannot carry a 32-byte key — audit::verify_spot_check's sampling seed
# is legitimate to log, and is exempted BY TYPE rather than by name.
check 'instrument u64 seed'      '#[instrument]\n    fn g(seed: u64) {}'                pass
check 'qualified instrument'     '#[tracing::instrument]\n    fn g(password: &str) {}'     catch
check 'qualified + pub(crate)'   '#[tracing::instrument]\n    pub(crate) fn g(dek: &[u8]) {}' catch

# event! / span! carry fields exactly like info! (#268 round 8)
check 'event! macro'          'tracing::event!(tracing::Level::INFO, password = %p);'   catch
check 'span! macro'           'tracing::span!(tracing::Level::INFO, "s", seed = %seed);' catch
check 'info_span! macro'      'tracing::info_span!("s", dek = %d);'                      catch
# fields(...) is recorded explicitly, so it SURVIVES skip_all
check 'skip_all + fields'     '#[instrument(skip_all, fields(password = %p))]\n    fn g() {}' catch

# MUST NOT FIRE — legitimate code, so the guard stays usable
check 'trailing comment'      'tracing::info!(alias = %a, "x"); // seed = thing'     pass
check 'public key_id'         'tracing::info!(key_id = %kid, "x");'                  pass
check 'seed_dir path'         'tracing::info!(seed_dir = %d, "x");'                  pass

[ "$fail" -eq 0 ] && echo "secret-logging guard self-test: 23/23 ✓"
exit "$fail"
