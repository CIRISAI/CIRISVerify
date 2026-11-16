# `ceg-genesis-bundle/2` known answers

`genesis_bundles_v1.json` (the cases) and `pool_0.json` .. `pool_3.json` (the statements they name, split
so each file stays under the repository's 1000 KB limit) hold genesis bundles of edition 2 (CC 2.6.1.11, CC 4.2.2.1, CC 3.2 T3, CC 5.3.4;
CIRISConstitution rc20 ae09856) with the verdict `ciris_verify_core::edition2::genesis::read_genesis_bundles`
must give each. `tests/genesis_bundle_v2_vectors.rs` replays them.

`gen_genesis_bundles.py` wrote it without verify's code: its own CBOR deterministic encoder and composite
signer (copied from `../gen_row_statements.py`), dilithium-py (FIPS 204, deterministic), pyca/cryptography
(Ed25519, X25519, X.509) and kyber-py (ML-KEM-768, so the seats' X-Wing keys are real keys, derived by the
draft-11 §5.2 expansion from the seeds the file states):

    pip install dilithium-py kyber-py cryptography
    python3 -I gen_genesis_bundles.py --cc /path/to/CIRISConstitution/tools/build_cc_signed_object_v2.py --out .

With `--cc` the generator also loads CC's tool (at ae09856), embeds its broken samples, and runs CC's
reference bundle reader over every first-bundle case, writing its answer beside ours (`cc.reader`). Without
`--cc` the `cc` section is absent and the Rust test's `cc_samples` fails, so regenerate with it.

## Parties

Key `n` is ML-DSA-65 seed `[n]*32` and Ed25519 seed `[n+100]*32`. Holders A, B, C, D are 1, 2, 3, 4 (D joins
in the later bundle); seats S1, S2 are 11, 12; witnesses 21, 22, 23; a stranger X is 9; 31 is another key
under A's name; 33 is a key C rotated to that no one holds. Holder `n`'s recovery key is key `n + 50`.

Each holder's `key:record` carries `attestation_evidence` = {`hardware_class` `YubiKey_5_FIPS`, `pq_custody`
`removable_offline`, `chain` [9c leaf, f9]}. The chain is minted under a **test-only mock attestation root**
(`attestation_root_der`, Ed25519): the f9 certificate carries the FIPS extension (`1.3.6.1.4.1.41482.3.10`),
the leaf firmware 5.7.4 (`.3`) and touch-always (`.8`), and the leaf attests the holder's Ed25519 half. The
reader takes its roots from a `TrustAnchorStore`: the test supplies the mock root; production passes
`trust_anchor_store::baked::default_store()`, under which these chains do not verify
(`the_baked_roots_refuse_the_mock_chain`). No test root is baked.

A seat's binding is an `identity:occurrence` row authored and signed by the seat, carrying
`transport_destination` (the RNS members, `destination_hash` computed by CC 3.3.6.3) and, beside it in the
signed payload, `transit_xwing_pubkey` and `onion_hop_xwing_pubkey` (1216 bytes each).

## Layout

- `pool_*.json`: every statement, by a 16-hex-digit prefix of its SHA-256; cases name statements from it.
- `seat_xwing`: each seat's two X-Wing public keys in full (placements carry their SHA-256).
- `cases`: in order. Each has `statements`, `rows` (`{id, statement}`: the rows held, by row id), `anchor`
  (`{thumbprints}`, `{object_id}` or null), `predecessors` (`{case}`: the Valid placement of an earlier case,
  or `{not_valid}`: an object id held and not Valid), `top_refused` (statements refused before their object
  is read) and `expect`, one entry per object id, sorted:
  - `verdict` `valid`, with `placement` (holders with kid, record, recovery commitment, class and custody;
    seats with kid, record, binding, `valid_until` and the SHA-256 of both X-Wing keys with their seeds; witnesses;
    `counted`; the charter's fuse and scope);
  - `invalid`, token `genesis_bundle_malformed`, `detail` the reason;
  - `waiting`, with `rows`, `prev` and `kids`;
  - `nothing`, with the token and, for a row or custody fault, `detail`;
  - `refused`: the statements of that object refused on their own (`index`, `fault`).
  Fork cases add `forks` (over the case's and its predecessors' Valid placements) and `head`.
- `recovery_commitments`: `[-16, SHA-256(CDE(["CEG-recovery/2", keys]))]` (CC 3.2 T3) over one key and over
  a set of two, with the input bytes.
- `cc`: CC's samples (genesis payloads, key-record payloads, recovery inputs, broken row statements), the
  reference reader's answer per first-bundle case, and its ten breaks mapped to our cases.

## Cases

Valid: a first bundle (thumbprint anchor; object-id anchor; with a stranger's statement refused; witnessed
mode); later bundles (C swapped for D, signed by A, B, D; by A, the removed C under its predecessor key, and
D; a changed recovery commitment its holder signs).

Invalid (`genesis_bundle_malformed`): `version_prev_mismatch` (version 2 with no prev, version 1 with a prev,
version 3 over version 1), `holders_seats_overlap` (holder/seat, seat/witness), `recovery_commitments_not_holders`,
`scope_missing_infra`, `witness_members_partial`, `witness_quorum_mismatch`, `federation_set_semantics_unsorted`,
`genesis_bundle_schema` (an edition-1 row-ref, a zero fuse), `family_key_id_changed`.

Waiting: a named row not held; a row held under another id; the predecessor not held; a removed holder's
statement under a key not held.

Concludes nothing: `genesis_bundle_count_unmet` (a missing holder, a bad iat, no iat, a bad signature, a kid not
the holder's, a row as a voice, a wrong typ; later: the added holder unsigned, a minority, a changed
commitment unsigned, a stranger); `genesis_bundle_not_anchored` (thumbprints, object id, no anchor, a second
first bundle under an object-id anchor); `genesis_bundle_row_unplaced` (a seat's binding not cited, a
stranger's record cited, two records for one holder); `genesis_bundle_row_invalid` (a bad row signature, a seat
not exactly `node`, a seat with no end, a holder not `accord_holder`, a holder record not its genesis key, a
record signed by another key, CC's three key-record samples, and nine binding faults: another signer, a short
or missing X-Wing key, a shared half, a half equal to the RNS x25519 or to the seat's Ed25519 half, the earlier
pair, `onion_relay.opt_out`, no `transport_destination`); `genesis_holder_custody` (not `removable_offline`, a
chain to an untrusted root, an attested key that is not the Ed25519 half, no FIPS, no chain, no evidence);
`genesis_bundle_prev_not_valid`.

Forks: two first bundles under a thumbprint anchor; two version-2 bundles naming one prev; and the chain to
its head.

## Agreement with CC's reference reader

CC's `read_bundle` (structure only, voices taken as verified) runs over the 20 first-bundle cases it can
model: 19 agree. The one disagreement is `iat_off_by_one`: CC answers Invalid `iat_mismatch` for the bundle;
this reader refuses that one statement (`iat` sits outside the object id, so one bad voice cannot make the
bundle's own bytes Invalid) and the bundle concludes nothing with the count unmet. Each of CC's ten reader
breaks maps to a case here (`cc.reader_breaks`). CC's eleven broken genesis payloads are each Invalid, its
three broken key records refused (`key_record_bad_pq_custody`, `key_record_bad_attestation_evidence` ×2),
its recovery input over no key refused, and its ten broken row statements each Invalid. CC's valid genesis
payload sample writes `scope` as `["infra:attest", "infra:serve"]`, which is not CDE set order; the reader
refuses it (`federation_set_semantics_unsorted`), and with `scope` re-sorted it is not Invalid.
