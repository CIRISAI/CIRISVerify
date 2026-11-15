# Extract the ML-DSA-65-Ed25519 known answers from the draft texts (args: lamps.txt jose.txt).
import base64, json, re, sys, hashlib
def clean(lines):
    return [l for l in lines if l.strip() and not re.match(r'^\s*(Ounsworth, et al\.|Prabel, et al\.|Internet-Draft)', l) and '\f' not in l]
L = open(sys.argv[1]).read().split('\n')
start = next(i for i, l in enumerate(L) if l.strip().startswith('"m": "VGhl'))
start = max(i for i in range(start) if L[i].strip() == '{')
body = ''.join(l.strip() for l in clean(L[start:]))
obj, _ = json.JSONDecoder().raw_decode(body)
tc = next(t for t in obj['tests'] if t['tcId'] == 'id-MLDSA65-Ed25519-SHA512')
b = lambda k: base64.b64decode(tc[k]).hex()
lamps = {"source": "draft-ietf-lamps-pq-composite-sigs-19 Appendix E, tcId id-MLDSA65-Ed25519-SHA512",
         "m_hex": base64.b64decode(obj['m']).hex(), "ctx_hex": base64.b64decode(obj['ctx']).hex(),
         "pk_hex": b('pk'), "sk_hex": b('sk'), "s_hex": b('s'), "s_with_context_hex": b('sWithContext')}
J = open(sys.argv[2]).read().split('\n')
end = next(i for i, l in enumerate(J) if 'Figure 12: ML-DSA-65-Ed25519' in l)
beg = next(i for i in range(end, 0, -1) if 'Figure 11:' in J[i])
blobs = [re.sub(r'\s', '', x) for x in re.findall(r"h'([0-9a-f\s]+)'", '\n'.join(clean(J[beg:end])))]
mldsa_seed, ed_seed, kid, pub, _sk, _, payload, mprime, _, _, sig = blobs
jose = {"source": "draft-ietf-jose-pq-composite-sigs-06 Figure 12 (ML-DSA-65-Ed25519); the draft's alg -59 is a requested value",
        "mldsa_seed_hex": mldsa_seed, "ed25519_seed_hex": ed_seed, "kid_hex": kid, "pub_hex": pub,
        "payload_hex": payload, "m_prime_hex": mprime, "signature_hex": sig}
for k, n in [("pk_hex", 1984), ("s_hex", 3373), ("s_with_context_hex", 3373)]:
    assert len(lamps[k]) == 2 * n, k
assert len(pub) == 3968 and len(sig) == 6746 and len(mprime) == 254
json.dump({"lamps_19": lamps, "jose_06": jose}, sys.stdout, indent=2, sort_keys=True); print()
