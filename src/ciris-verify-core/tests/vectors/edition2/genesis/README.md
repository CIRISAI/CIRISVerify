# `ceg-genesis-bundle/2` known answers

Three versions live here.

- **v3** (replayed): `genesis_bundles_v3.json` (the cases) and `pool_v3_0.json` .. `pool_v3_7.json` (the
  statements they name), written by `gen_genesis_bundles_v3.py` against CIRISConstitution v1.0-rc21-wire e6fd7c6
  (CC 2.6.1.11, CC 4.2.6, CC 4.2.2.1, CC 3.3.6.2, CC 3.2 T3, CC 5.3.4). `tests/genesis_bundle_v3_vectors.rs`
  replays them through `ciris_verify_core::edition2::genesis::read_genesis_bundles`.
- **v2** (kept byte-identical, no longer replayed): `genesis_bundles_v2.json` and `pool_v2_0.json` ..
  `pool_v2_7.json`, written by `gen_genesis_bundles_v2.py` against rc20 64c5918. At v1.0-rc21-wire e6fd7c6 a seat's
  binding is the seat's own `identity:occurrence`, checked by that family's payload rule as it is alone, with
  `identity_key_id` = `occurrence_key_id` = the seat's identity reference and `device_class` `server`. None
  of v2's bindings carries those members, so v2's valid bundles no longer verify.
- **v1** (kept byte-identical, no longer replayed): `genesis_bundles_v1.json` and `pool_0.json` ..
  `pool_3.json`, written by `gen_genesis_bundles.py` against rc20 ae09856. CC cites v1 at verify 1658f33. At
  64c5918 a seat's binding must name its key record in `refs`, which none of v1's bindings does, so v1's
  valid bundles no longer verify.

Beside them, an additive set: `genesis_reseat_v2.json` (cases and their statements in one file), written by
`gen_genesis_reseat_v2.py` over `gen_genesis_bundles_v3.py`'s machinery (loaded as a module, its own outputs
sent to a throwaway directory) against v1.0-rc21-wire e6fd7c6 (CC 2.6.1.11, CC 2.6.1.7, CC 3.3.6.2), and replayed by
`tests/genesis_reseat_v2_vectors.rs`. A later bundle over v3's `first_valid` (repeated as its first case)
re-seats S1 at a new key S1N (Key 13): S1's new key record and its binding carry `iss` = `author` = S1's
identity reference and are signed by S1N; the binding's `identity_key_id` and `occurrence_key_id` are S1's
identity reference too, never S1N's. `reseat_seat_new_key` is Valid, S1 placed at S1N's key, record,
binding and X-Wing keys; the same bundle with the binding signed by S1's previous key
(`reseat_binding_signed_by_old_key`) or by an unrelated key U, Key 14 (`reseat_binding_signed_by_unrelated_key`)
concludes nothing, `genesis_bundle_row_invalid` / `row_signer`; and with a binding whose `identity_key_id` and
`occurrence_key_id` name S1N (`reseat_binding_names_new_key`), `genesis_bundle_row_invalid` / `row_invalid`.
`genesis_reseat_v1.json` (`gen_genesis_reseat_v1.py`, rc20, over v2) stays byte-identical and is no longer
replayed.

Each pool is split by the first hex digit of its keys so every file stays under the repository's 1000 KB
limit.

The generators share no code with verify: their own CBOR deterministic encoder and composite signer
(copied from `../gen_row_statements.py`), dilithium-py (FIPS 204, deterministic), pyca/cryptography (Ed25519,
X25519, X.509) and kyber-py (ML-KEM-768, so the seats' X-Wing keys are real keys, derived by the draft-11 §5.2
expansion from the seeds the file states):

    pip install dilithium-py kyber-py cryptography
    git -C /path/to/CIRISConstitution show v1.0-rc21-wire:tools/build_cc_signed_object_v2.py > /tmp/cc_tool.py
    python3 -I gen_genesis_bundles_v3.py --cc /tmp/cc_tool.py --out .
    python3 -I gen_genesis_reseat_v2.py --out .

With `--cc` the generator also loads CC's tool (at v1.0-rc21-wire e6fd7c6), embeds its broken samples, and runs CC's
reference bundle reader over every case it can model, writing its answer beside ours (`cc.reader`). Later
bundles are read over the reference reader's own placement of their predecessor. Without `--cc` the `cc`
section is absent and the Rust test's `cc_samples` fails, so regenerate with it.

## Parties

Key `n` is ML-DSA-65 seed `[n]*32` and Ed25519 seed `[n+100]*32`. Holders A, B, C, D are 1, 2, 3, 4 (D joins
in a later bundle); seats S1, S2 are 11, 12; witnesses 21, 22, 23; a stranger X is 9; 31 is another key
under A's name; 33 is a key C rotated to that no one holds. Holder `n`'s recovery key is key `n + 50`. A's
signing key after its first recovery is 41 and after its second 42; A's next recovery keys are 61 and 62; 71
is a key no commitment names.

Each holder's `key:record` carries `attestation_evidence` = {`hardware_class` `YubiKey_5_FIPS`, `pq_custody`
`removable_offline`, `chain` [9c leaf, f9]}. The chain is minted under a **test-only mock attestation root**
(`attestation_root_der`, Ed25519): the f9 certificate carries the FIPS extension (`1.3.6.1.4.1.41482.3.10`),
the leaf firmware 5.7.4 (`.3`) and touch-always (`.8`), and the leaf attests the holder's Ed25519 half. The
reader takes its roots from a `TrustAnchorStore`: the test supplies the mock root; production passes
`trust_anchor_store::baked::default_store()`, under which these chains do not verify
(`the_baked_roots_refuse_the_mock_chain`). No test root is baked.

A seat's binding is an `identity:occurrence` row authored and signed by the seat, carrying
`transport_destination` (the RNS members, `destination_hash` computed by CC 3.3.6.3), beside it in the
signed payload `transit_xwing_pubkey` and `onion_hop_xwing_pubkey` (1216 bytes each), (v2) `refs`
naming the seat's own key record under `also` / `cites`, and (v3) `identity_key_id` and `occurrence_key_id`,
both the seat's identity reference (its `author`, `iss` and CWT `sub`), and `device_class` `server`.

A recovery key's record is a `key:record` authored under the holder's identity reference and signed by the
recovery key; a recovery bundle names it in `cites` beside the holder's new signing-key record.

## Layout

- `pool_v3_*.json`: every statement, by a 16-hex-digit prefix of its SHA-256; cases name statements from it.
- `seat_xwing`: each seat's two X-Wing public keys in full (placements carry their SHA-256).
- `cases`: in order. Each has `statements`, `rows` (`{id, statement}`: the rows held, by row id), `anchor`
  (`{thumbprints}`, `{object_id}` or null), `predecessors` (`{case}`: the Valid placement of an earlier case,
  or `{not_valid}`: an object id held and not Valid), `top_refused` (statements refused before their object
  is read) and `expect`, one entry per object id, sorted:
  - `verdict` `valid`, with `placement` (holders with kid, record, recovery commitment, class and custody;
    seats with kid, record, binding, `valid_until` and the SHA-256 of both X-Wing keys with their seeds;
    witnesses; `counted`; the charter's fuse and scope; `recovered`; `spent_commitments` and
    `lineage_commitments`, accumulated along the chain);
  - `invalid`, token `genesis_bundle_malformed`, `detail` the reason;
  - `waiting`, with `rows`, `prev` and `kids`;
  - `nothing`, with the token and, for a row, custody or commitment fault, `detail`;
  - `refused`: the statements of that object refused on their own (`index`, `fault`).
  Fork cases add `forks` (over the case's and its predecessors' Valid placements), `head`, and `common`:
  the lineage's tips and the holders (same key) and seats (same key and X-Wing keys) every tip names, or
  null for a fork of the genesis.
- `recovery_commitments`: `[-16, SHA-256(CDE(["CEG-recovery/2", keys]))]` (CC 3.2 T3) over one key and over
  a set of two, with the input bytes.
- `cc`: CC's samples (genesis payloads, key-record payloads, recovery inputs, bindings, `identity:occurrence`
  payloads (v3), broken row statements), the reference reader's answer per case it models, and its breaks, valid samples and
  cross-bundle checks mapped to our cases.

## Cases (v3)

Every v2 case is kept, each binding carrying the three occurrence members; no verdict changed (only the row
ids, object ids and placement digests that follow from the new binding bytes). The new check runs in
`check_seat_binding` after the transport and X-Wing checks and before `binding_names_no_record`; every v3
case breaks one rule, so the order moves no verdict.

New, each `genesis_bundle_row_invalid` / `row_invalid` inside a bundle (and `row_invalid` from
`check_seat_binding` alone): `binding_no_identity_key_id`, `binding_no_occurrence_key_id`,
`binding_no_device_class`, `binding_device_class_laptop`, `binding_device_class_phone` (CC's reader sample),
`binding_device_class_unlisted` (`tablet`, outside the closed set), `binding_identity_key_id_other` and
`binding_occurrence_key_id_other` (seat 2's identity reference), `binding_identity_key_id_not_iref` (a bare
label), and `binding_sub_not_seat` (the members are the seat, the CWT `sub` is seat 2; CC's reader
projection carries no `sub`, so it does not model this case). CC's five `identity:occurrence` payload
samples (`family_payload_samples`, one valid, four broken) are replayed through
`edition2::genesis::check_identity_occurrence`. CC's binding samples carry the CC 3.3.6.2 members alone, so
the test reads each with the seat's occurrence members added.

## Cases (v2)

Every v1 case is kept. One verdict changed: `later_voice_key_not_held` (C signs a later bundle under a key C
rotated to) is no longer Waiting on that key. At 64c5918 a later bundle counts statements "each under the key
the predecessor names", so that statement is refused (`statement_kid_not_iss`) and the count is unmet.

New:

- Recovery: `recovery_valid` (one statement by A's recovery key; A's new record; the next commitment; A's first
  commitment spent); `second_recovery_valid` (A again, under the key its first recovery committed).
- Its count (`genesis_bundle_count_unmet`): `recovery_commitment_mismatch` (a named key A's commitment does not
  commit to; A's current signing key; the recovery key's record not named); `recovery_commitment_spent` (the
  next commitment equal to the one spent; a second recovery under the spent key; a second recovery re-listing
  the spent commitment; a roster bundle re-listing it, `relisted_spent_commitment`); a bad signature (refused,
  count unmet).
- Its Invalid rules (`genesis_bundle_malformed`): `recovery_key_is_signing_key` (the recovery key itself; B's
  recovery key, which a commitment of the lineage names), `recovery_reuses_signing_key`,
  `recovery_changes_other_seat` (another holder re-committed; the charter's fuse; a seat dropped).
- `holder_not_genesis_key` read against the bundle in force: a recovered holder's new record passes in the
  next roster bundle (`recovered_holder_seated_key`). A roster bundle re-seats a holder under a new key only where
  that holder's statement under its current key counts: `roster_bundle_rotates_holder_key` (A signs under
  its genesis key: Valid, A seated at the new key), `roster_bundle_rotates_without_holder_voice` (B and C
  only: `holder_not_genesis_key`), `roster_bundle_rotates_holder_voice_under_new_key` (A's statement under
  the new key refused `statement_kid_not_iss`; B and C meet the count; `holder_not_genesis_key`), and
  `roster_after_rotation_counts_new_key` (the next bundle counts A under the new key: Valid).
- `holder_key_retired` (`genesis_bundle_malformed`): no later bundle seats a holder at a key its lineage
  retired (one the holder was seated at and left, or a recovery key a recovery spent) or at the key its
  in-force recovery commitment commits to. `roster_reseats_retired_key_after_rotation` and
  `roster_reseats_retired_key_after_recovery` (A's genesis key back, with A's own statement),
  `recovered_holder_genesis_record` (the same without A's statement: the check reads the payload and the
  predecessor only, so it answers before `holder_not_genesis_key`), `roster_seats_in_force_recovery_key`,
  `roster_seats_spent_recovery_key`. Placements carry `retired_holder_keys`.
- Seats and bindings (`genesis_bundle_row_invalid`): `seat_record_ended` (at and before the bundle's instant),
  `binding_names_no_record` (no `refs`; another seat's record), and CC's binding samples (an X-Wing key inside
  `transport_destination`, a text `destination_hash`, `opt_out: false`: `row_invalid`).
- `scope_unsorted`; `fork_roster_and_recovery` (a roster change and a recovery on one predecessor: a fork whose
  tips share B and both seats).

## Agreement with CC's reference reader (v1.0-rc21-wire e6fd7c6)

v3: CC's `read_bundle` (at rc21 893534b, the first change after v1.0-rc21-wire; text and schemas unchanged
since the tag), which checks a seat binding's `identity_key_id`, `occurrence_key_id`, `device_class` and
`refs.head`, runs over the 70 cases it can model (v2's 60 and ten new binding cases): all 70 agree. Every
binding names its self-roster head in `refs.head`, the seat's own key record (a seat binding is the seat's
first bind, CC 3.3.6.4). CC's three new reader breaks (`a seat binding with no identity_key_id`, `a seat
binding of device_class phone`, `a seat binding without refs.head`) map to `binding_no_identity_key_id`,
`binding_device_class_phone` and `binding_no_head`.

v2: CC's `read_bundle` (structure only, voices taken as verified) runs over the 60 cases it can model, first
bundles and later ones: all 60 agree at rc20 436b5bc, which adds the seated-key check (holder rotation
by the holder's own counted voice), `holder_key_retired`, and the Invalid-first order. A refused statement
is no voice, so the projection carries counted voices only. (At 64c5918, 53 of 60 agreed.) Each of CC's 24 reader breaks maps to a case here with the same answer, its two valid later
samples to Valid cases, and its three cross-bundle checks to cases. CC's genesis payload samples (the valid
one now in set order), key-record samples, recovery inputs and broken row statements are replayed as in v1;
its five broken binding samples are each refused by `check_seat_binding`, and its valid one passes (v3: with
the seat's occurrence members added).

## One device per holder (`genesis_holder_device_v1.json`)

`gen_genesis_holder_device_v1.py` writes `genesis_holder_device_v1.json` (SHA-256
`25b96ebfd1f17087c0b0aab27144dcc8c8b20eb358d60b35ebee5ea2f3c45886`). The rule is CC 4.2.3 "One device per holder", with
refusal `holder_device_shared`, from CIRISConstitution v1.0-rc21 b016df4. The generator loads
`gen_genesis_bundles_v3.py` beside it, runs it into a scratch directory and discards that output, then
reuses its encoder, signer, mock PKI and case machinery. To that it adds only the 9c leaf's serial
extension (`1.3.6.1.4.1.41482.3.7`, a DER INTEGER) and eight first-bundle cases:

| Case | Leaves | Verdict |
|------|--------|---------|
| `distinct_serials` | Each holder names its own serial (the July serials) under its own f9 | Valid |
| `shared_serial` | A and B name one serial | `holder_device_shared` |
| `shared_serial_all` | All three name one serial | `holder_device_shared` |
| `shared_f9_distinct_serials` | One f9 signs all three leaves; distinct serials | Valid |
| `shared_f9_shared_serial` | One f9; A and C share a serial | `holder_device_shared` |
| `one_leaf_names_no_device` | A's leaf has no serial | Valid |
| `two_leaves_name_no_device` | A's and B's leaves have no serial | Valid |
| `serial_not_integer` | A's serial extension is an OCTET STRING | nothing: `genesis_holder_custody` / `custody_serial_malformed` |

The device is read only from a leaf that passed the custody gate. A leaf that names no device is not
compared, because CC 4.2.3 binds only where a leaf names one. A serial extension that is present but is not one DER INTEGER fitting u32 is not read as naming no device: it fails the custody gate. The file has the v3 case file's shape,
with its statements inline under `pool`. `holder_device_cases` in `tests/genesis_bundle_v3_vectors.rs`
replays it.

    python3 -I gen_genesis_holder_device_v1.py > genesis_holder_device_v1.json

## Recovery commitments (`genesis_commitments_v1.json`)

`gen_genesis_commitments_v1.py` writes `genesis_commitments_v1.json`, SHA-256
`f8ecd5f46f4d0b4db81594eb78b7df0466c7b16045c3755a7fea30e3ff98c254`. It is built over the v3
generator in the same way as the holder-device file. It covers two CC 4.2.6 rules that apply to
every bundle, the first one included:
- `recovery_commitment_shared`: two seated holders carry one commitment.
- `recovery_commitment_is_holder_key`: a commitment is over a signing key the bundle seats, the
  holder's own or another holder's.

CIRISServer's trust-root audit found the gap. It has 7 cases: a valid first bundle, three
first-bundle refusals, a valid later bundle that moves a commitment to a fresh key, and two
later-bundle refusals. A commitment hashes a key set, so a reader sees only an equal set;
overlapping sets are for the ceremony to refuse when the bundle is minted. `recovery_commitment_cases`
in `tests/genesis_bundle_v3_vectors.rs` replays it.
